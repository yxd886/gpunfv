#ifndef LOAD_BALANCER_CUH
#define LOAD_BALANCER_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "../include/packet_parser.cuh"
#include "../include/gpu_interface.hh"

#define IP_NUM		10		// Rule amount
#define MAC_NUM		10		// Rule amount

using namespace std;

struct flow_dst{
	uint32_t ip_daddr;			// destination ip address (network byte order)
	struct ether_addr eth_d_addr[MAC_NUM];
};

struct flow_table{
	struct flow_dst dst[IP_NUM];
	int current_id;
};


class load_balancer_flow_state {
public:
	bool exist;
	uint32_t ip_daddr;
	int ip_pos;
	int eth_pos;
};

class gpu_flow_table {
public:	
	uint32_t size;
	flow_table* _table;

	__host__ flow_table(size_t s, void *r) : size(s) {
		uint32_t real_data_size = sizeof(flow_table) * size;

		// Copy real data to gpu and set the device pointer
		_table = (flow_table *)gpu_malloc_set(real_data_size, r);
	}

};

void *init_nf_info(size_t size, void *data) {
	gpu_flow_table info(size, data);

	// Copy Infos to gpu
	 return gpu_malloc_set(sizeof(info), &info);
}

class load_balancer {
public:
	// Convert 4 integers to a network byte order ip address
	__device__ inline static uint32_t i2ip(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3) {
		uint32_t res;
		uint8_t *p = (uint8_t *) &res;

		*(p + 0) = s0;
		p[1] = s1;
		p[2] = s2;
		p[3] = s3;

		return res;
	}

	__device__ inline static void init_automataState(load_balancer_flow_state &state) {
		state.exist = false;
		state.ip_daddr = 0;
		state.ip_pos = 0;
		state.eth_pos = 0;
	}

	__device__ inline static void nf_logic(void *pkt, load_balancer_flow_state *state, gpu_flow_table *table) {
		process(pkt, state, table);
	} 

private:
	__device__ inline static void process(void *packet, load_balancer_flow_state* state, gpu_flow_table *table) {
		packetInfo info;
		packetParser::parse_raw_packet(packet, &info);
		if(state->exist ==false){
			state->exist =true;
			state->ip_pos = table->_table->current_id;
			table->_table->current_id = (table->_table->current_id+1)%IP_NUM;
			state->ip_daddr = table->_table->dst[state->ip_pos].ip_daddr;
		info._ipv4_hdr->dst_addr = state->ip_daddr;
		eth_copy(&(info._eth_hdr->d_addr),&(table->_table->dst[state->ip_pos].eth_d_addr[state->eth_pos]));
		state->eth_pos = (state->eth_pos+1)%MAC_NUM;

		}
	}
	
	__device__ inline static void eth_copy(struct ether_addr* dst, struct ether_addr* src){
		dst->addr_bytes[0]=src->addr_bytes[0];
		dst->addr_bytes[1]=src->addr_bytes[1];
		dst->addr_bytes[2]=src->addr_bytes[2];
		dst->addr_bytes[3]=src->addr_bytes[3];
		dst->addr_bytes[4]=src->addr_bytes[4];
		dst->addr_bytes[5]=src->addr_bytes[5];
	}

};

#endif // LOAD_BALANCER_CUH