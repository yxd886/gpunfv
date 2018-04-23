#ifndef SERVICE_CHAIN_CUH
#define SERVICE_CHAIN_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "../include/packet_parser.cuh"
#include "../include/gpu_interface.hh"
#include "../firewall/firewall.cuh"
#include "../l2_forward/ips.cuh"

class chain_flow_state{
public:
	ips_flow_state _ips_state;
	firewall_flow_state _firewall_state;
};

class chainInfo {
public:
	Rules *_rules;
	gpu_IPS *_ips;

	chainInfo(void *rules, void *ips) : _rules((Rules *) rules), _ips((gpu_IPS *) ips) {}
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
		Firewall::nf_logic(pkt, &state->_firewall_state, info->_rules);

		// suppose all packet can pass the firewall
		IPS::nf_logic(pkt, &state->_ips_state, info->_ips->dfa_arr);
	}
};

#endif // SERVICE_CHAIN_CUH