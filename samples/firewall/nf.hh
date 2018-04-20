#ifndef NF_HH
#define NF_HH

#include "firewall.hh"

typedef class Firewall NF;						// specify NF class
typedef class firewall_flow_state nf_flow_state;	// specify NF state class
//using nf_pkt = rte_packet;				// specify NF packet class
inline void NF::nf_logic(void *pkt, nf_flow_state *state) {	// specify nf logic function
    process(pkt, state);
}

#endif