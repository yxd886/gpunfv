#ifndef SERVICE_CHAIN_HH
#define SERVICE_CHAIN_HH

#include "../flow_monitor/flow_monitor.hh"
#include "../ips/ips.hh"
#include "../load_balancer/load_balancer.hh"

struct chain_flow_state{
    flow_monitor_flow_state _flow_monitor_state;
    ips_flow_state _ips_state;
	load_balancer_flow_state _load_balancer_state;

};

class serviceChain {
    flow_monitor _flow_monitor;
	IPS _ips;
	load_balancer _load_balancer;
public:
	void *info_for_gpu;

	serviceChain() {
		init_nf();
	}

	void init_nf() {
		info_for_gpu = init_service_chain_info(_flow_monitor.info_for_gpu, _ips.info_for_gpu,_load_balancer.info_for_gpu);
	}

	inline void init_automataState(chain_flow_state &state) {

	    _flow_monitor.init_automataState(state._flow_monitor_state);
	    _ips.init_automataState(state._ips_state);
        _load_balancer.init_automataState(state._load_balancer_state);


	}

	inline void nf_logic(void *pkt, chain_flow_state *state) {

	    _flow_monitor.nf_logic(pkt, &state->_flow_monitor_state);
	    _ips.nf_logic(pkt, &state->_ips_state);
		_load_balancer.nf_logic(pkt, &state->_load_balancer_state);

	}
};


#endif // SERVICE_CHAIN_HH
