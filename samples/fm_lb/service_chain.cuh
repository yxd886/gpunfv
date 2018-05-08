#ifndef SERVICE_CHAIN_CUH
#define SERVICE_CHAIN_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "../include/packet_parser.cuh"
#include "../include/gpu_interface.hh"
#include "../firewall/firewall.cuh"
#include "../flow_monitor/flow_monitor.cuh"
#include "../load_balancer/load_balancer.cuh"

class chain_flow_state{
public:
    flow_monitor_flow_state _flow_monitor_state;
	load_balancer_flow_state _load_balancer_state;

};

class chainInfo {
public:
	flow_monitor_Rules* _fm_rules;

	gpu_flow_table* _flow_tables;

	chainInfo(void *fm_rules, void* lb) : _fm_rules((flow_monitor_Rules *) fm_rules),_flow_tables((gpu_flow_table*)lb) {}
};

// Copy infomation for nf to use in GPU
void *init_service_chain_info(void *d1, void *d2) {
	chainInfo info(d1, d2);

	// Copy Infos to gpu
	return gpu_malloc_set(sizeof(info), &info);
}

class serviceChain {
public:
	__device__ inline static void nf_logic(void *pkt, chain_flow_state *state, chainInfo *info) {
		
		flow_monitor::nf_logic(pkt,&state->_flow_monitor_state,info->_fm_rules);
		load_balancer::nf_logic(pkt, &state->_load_balancer_state, info->_flow_tables);
	}
};

#endif // SERVICE_CHAIN_CUH