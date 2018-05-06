#ifndef NF_CUH
#define NF_CUH

#include "load_balancer.cuh"

typedef class load_balancer  NF;						// specify NF class
typedef class load_balancer_flow_state nf_flow_state;	// specify NF state class
typedef class gpu_flow_table Infos;

#endif // NF_CUH