#ifndef LOAD_BALANCER_HH
#define LOAD_BALANCER_HH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

//#include "../include/vector.hh"

#include "../include/packet_parser.hh"
#include "../include/gpu_interface.hh"

using namespace std;

#define MAX_IP_NUM	10000000	// Maximum rule amount
#define IP_NUM		10		// Rule amount
#define MAC_NUM		10		// Rule amount

//void *gpu_init(unsigned size, void *ptr);

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
	//time_t createdTime;
	//time_t refreshTime;
	bool exist;
	uint32_t ip_daddr;
	int ip_pos;
	int eth_pos;
};

class load_balancer {
	flow_table _flow_table;
public:
	void *info_for_gpu;

	load_balancer() : info_for_gpu(0) {
		int n = IP_NUM;
		assert(n > 0 && n < MAX_IP_NUM);
		for(int i = 0; i < n; i++) {
			_flow_table.dst[i].ip_daddr = i2ip((i >> 24) % 256, (i >> 16) % 256, (i >> 8) % 256, i % 256);		// source ip 0~n
			for(int j = 0; j < MAC_NUM; j++){
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[0]=(i >> 24) % 256;
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[1]=(i >> 16) % 256;
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[2]=(i >> 8) % 256;
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[3]=(i >> 4) % 256;
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[4]=(i >> 10) % 256;
				_flow_table.dst[i].eth_d_addr[j].addr_bytes[5]= i % 256;
			}
		}

		nf_init();
	}

	inline void nf_init() {

		info_for_gpu = init_nf_info(1, &_flow_table);
	}

	// Convert 4 integers to a network byte order ip address
	inline uint32_t i2ip(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3) {
		uint32_t res;
		uint8_t *p = (uint8_t *) &res;

		*(p + 0) = s0;
		p[1] = s1;
		p[2] = s2;
		p[3] = s3;

		return res;
	}

	inline void init_automataState(load_balancer_flow_state &state) {
		state.exist = false;
		state.ip_daddr = 0;
		state.ip_pos = 0;
		state.eth_pos = 0;

	}

	inline void nf_logic(void *pkt, load_balancer_flow_state *state) {	// specify nf logic function
	    process(pkt, state);
	}

private:
	inline void process(void *packet, load_balancer_flow_state* state) {
		packetInfo info;
		rte_prefetch0((void*)packet);
		packetParser::parse_raw_packet(packet, &info);
		if(state->exist ==false){
			state->exist =true;
			state->ip_pos = _flow_table.current_id;
			_flow_table.current_id = (_flow_table.current_id+1)%IP_NUM;
			state->ip_daddr = _flow_table.dst[state->ip_pos].ip_daddr;

		}
		info._ipv4_hdr->dst_addr = state->ip_daddr;
		eth_copy(&(info._eth_hdr->d_addr),&(_flow_table.dst[state->ip_pos].eth_d_addr[state->eth_pos]));
		state->eth_pos = (state->eth_pos+1)%MAC_NUM;

	}
	void eth_copy(struct ether_addr* dst, struct ether_addr* src){
		dst->addr_bytes[0]=src->addr_bytes[0];
		dst->addr_bytes[1]=src->addr_bytes[1];
		dst->addr_bytes[2]=src->addr_bytes[2];
		dst->addr_bytes[3]=src->addr_bytes[3];
		dst->addr_bytes[4]=src->addr_bytes[4];
		dst->addr_bytes[5]=src->addr_bytes[5];
	}



};

#endif /* LOAD_BALANCER_HH */
