#ifndef SERVICE_CHAIN_CUH
#define SERVICE_CHAIN_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "../include/packet_parser.cuh"
#include "../include/gpu_interface.hh"
#include "../ips/ips.cuh"
#include "../firewall/firewall.cuh"
#include "../load_balancer/load_balancer.cuh"

class chain_flow_state{
public:
    firewall_flow_state _firewall_state;
    ips_flow_state _ips_state;
	load_balancer_flow_state _load_balancer_state;

};

class chainInfo {
public:
	Rules* rules;
	gpu_IPS *_ips;
	gpu_flow_table* _flow_tables;

	chainInfo(void *rules, void *ips, void* lb) : rules((Rules *) rules), _ips((gpu_IPS *) ips),_flow_tables((gpu_flow_table*)lb) {}
};

// Copy infomation for nf to use in GPU
void *init_service_chain_info(void *d1, void *d2, void* d3) {
	chainInfo info(d1, d2, d3);

	// Copy Infos to gpu
	return gpu_malloc_set(sizeof(info), &info);
}

class serviceChain {
public:
	__device__ inline static void nf_logic(void *pkt, chain_flow_state *state, chainInfo *info) {
		
		Firewall::nf_logic(pkt,&state->_firewall_state,info->rules);
		IPS::nf_logic(pkt, &state->_ips_state, info->_ips->dfa_arr);
		load_balancer::nf_logic(pkt, &state->_load_balancer_state, info->_flow_tables);
	}
};

#endif // SERVICE_CHAIN_CUH