#ifndef SERVICE_CHAIN_HH
#define SERVICE_CHAIN_HH

#include "../firewall/firewall.hh"
#include "../l2_forward/ips.hh"

struct chain_flow_state{
	ips_flow_state _ips_state;
	firewall_flow_state _firewall_state;
};

class serviceChain {
	Firewall _firewall;
	IPS _ips;
public:
	void *info_for_gpu;

	serviceChain() {
		init_nf();
	}

	void init_nf() {
		info_for_gpu = init_service_chain_info(_firewall.info_for_gpu, _ips.info_for_gpu);
	}

	inline void init_automataState(chain_flow_state &state) {
		_firewall.init_automataState(state._firewall_state);
		_ips.init_automataState(state._ips_state);
	}

	inline void nf_logic(void *pkt, chain_flow_state *state) {
		_firewall.nf_logic(pkt, &state->_firewall_state);
		_ips.nf_logic(pkt, &state->_ips_state);
	}
};


#endif // SERVICE_CHAIN_HH