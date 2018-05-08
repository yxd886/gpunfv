#ifndef FLOW_MONITOR_CUH
#define FLOW_MONITOR_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "../include/packet_parser.cuh"
#include "../include/gpu_interface.hh"

using namespace std;

struct flow_monitor_Rule{
	uint32_t saddr;			// source ip address (network byte order)
	uint32_t daddr;			// destination ip address (network byte order)
	uint32_t smask;			// source network mask (host byte order)
	uint32_t dmask;			// destination network mask (host byte order)
	uint16_t sport, dport;  // source port, destination port
	uint8_t protocol;		// protocol type
	enum {PASS, DROP};		// action id
	uint8_t action;			// action
};

class flow_monitor_flow_state {
public:
	int match_no;
	int drop_no;
	int pass_no;
	bool current_pass;
	int counter;
	int total_byte;
	int protocol_type;
};

class flow_monitor_Rules {
public:	
	uint32_t size;
	flow_monitor_Rule *rules;
	//uint32_t data_size;

	__host__ flow_monitor_Rules(size_t s, void *r) : size(s) {
		uint32_t real_data_size = sizeof(flow_monitor_Rule) * size;

		// Copy real data to gpu and set the device pointer
		rules = (flow_monitor_Rule *)gpu_malloc_set(real_data_size, r);
	}

	__device__ inline flow_monitor_Rule& operator[](size_t idx) {
		return rules[idx];
	}
};

void *init_flow_monitor_info(size_t size, void *data) {
	flow_monitor_Rules info(size, data);

	// Copy Infos to gpu
	 return gpu_malloc_set(sizeof(info), &info);
}

class flow_monitor {
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

	__device__ inline static void init_automataState(flow_monitor_flow_state &state) {
		state.match_no = 0;
		state.drop_no = 0;
		state.pass_no = 0;
		state.current_pass = 0;
		state.counter = 0;
		state.total_byte = 0;
		state.protocol_type = 0;
	}

	__device__ inline static void nf_logic(void *pkt, flow_monitor_flow_state *state, flow_monitor_Rules *rules) {
		process(pkt, state, rules);
	} 

private:
	__device__ inline static void process(void *packet, flow_monitor_flow_state* state, flow_monitor_Rules *rules) {
		packetInfo info;

		packetParser::parse_raw_packet(packet, &info);
		match_rules(&info, state, rules);
		state->total_byte += info._size;
		state->protocol_type += info._protocol;
	}

	__device__ inline static bool ip_eq_mask(uint32_t addr1, uint32_t addr2, uint32_t mask) {
		return (net::myntohl(addr1) & mask) == (net::myntohl(addr2) & mask);
	}

	__device__ static void match_rules(packetInfo *info, flow_monitor_flow_state* state, flow_monitor_Rules *rules) {
		uint32_t s_addr, d_addr;
		uint16_t s_port, d_port;
		uint8_t protocol;

		s_addr = info->_ipv4_hdr->src_addr;
		d_addr = info->_ipv4_hdr->dst_addr;
		protocol = info->_protocol;

		if(protocol == packetInfo::TCP) {
			s_port = info->_tcp_hdr->src_port;
			d_port = info->_tcp_hdr->dst_port;
		}
		else if(protocol == packetInfo::UDP) {
			s_port = info->_udp_hdr->src_port;
			d_port = info->_udp_hdr->dst_port;
		}
		else {
			assert(0 && "Unsupported protocol.");
		}
	
		state->counter++;

		bool drop;
		uint32_t i;

		// Match rules
		for(i = 0; i < (*rules).size; i++){
			flow_monitor_Rule temp = (*rules)[i];	

			if(temp.saddr == ANY_ADDR ? false : 
					!ip_eq_mask(temp.saddr, s_addr, temp.smask))
				continue;

			if(temp.daddr == ANY_ADDR ? false : 
					!ip_eq_mask(temp.daddr, d_addr, temp.dmask))
				continue;

			if(temp.protocol == ANY_PROTOCOL ? false : !(temp.protocol == protocol))
				continue;

			if(temp.sport == ANY_PORT ? false : !(temp.sport == s_port))
				continue;
			
			if(temp.dport == ANY_PORT ? false : !(temp.dport == d_port))
				continue;

			// Perfect match
			state->match_no++;

			if(temp.action == flow_monitor_Rule::PASS)
				drop = false;
			else if(temp.action == flow_monitor_Rule::DROP)
				drop = true;
			else
				assert(0 && "Unexpected action id");
		
			break;
		}

		if(i >= (*rules).size || drop) { 	// Match nothing or match a rule of drop, drop the packet
			state->drop_no++;
			state->current_pass = false;

			//printf("DROP\n");
		}
		else {
			state->pass_no++;
			state->current_pass = true;

			//printf("PASS\n");
		}
	}

};

#endif // FLOW_MONITOR_CUH