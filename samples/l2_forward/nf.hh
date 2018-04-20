#ifndef NF_HH
#define NF_HH

#include "ips.hh"

using NF = IPS;                         // specify NF class
using nf_flow_state = ips_flow_state;   // specify NF state class
//using nf_pkt = rte_packet;              // specify NF packet class
inline void NF::nf_logic(void *pkt, nf_flow_state *state) {   // specify nf logic function
    ips_detect(pkt, state);
}


#endif