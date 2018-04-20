#ifndef NF_CUH
#define NF_CUH

#include "firewall.cuh"

typedef class Firewall NF;						// specify NF class
typedef class firewall_flow_state nf_flow_state;	// specify NF state class
typedef class Rules Infos;
//using nf_pkt = rte_packet;				// specify NF packet class
__device__ inline void NF::nf_logic(void *pkt, nf_flow_state *state, Infos *info) {	// specify nf logic function
    process(pkt, state, info);
}

#endif // NF_CUH