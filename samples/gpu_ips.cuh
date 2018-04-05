#ifndef GPU_IPS_CUH
#define GPU_IPS_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cuda_runtime.h>
#include <helper_cuda.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

#include "common.cuh"
#include "../nf/aho-corasick/fpp.h"
#include "../nf/aho-corasick/aho.hh"

#define MAX_MATCH 8192
#define MAX_PKT_SIZE 1500
#define DFA_NUM 10

struct ips_flow_state{

    uint16_t _state[DFA_NUM];
    int _dfa_id[DFA_NUM];
    bool _alert[DFA_NUM];
};
struct PKT{

	char pkt[MAX_PKT_SIZE];
};
struct mp_list_t {
    int num_match;
    uint16_t ptrn_id[MAX_MATCH];
};

struct gpu_IPS{ 
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
};



__global__ void childKernel(const struct aho_dfa *dfa_arr,    
   const struct aho_pkt *pkts, struct ips_flow_state *ips_state)  
{  
    int tid = blockIdx.x*blockDim.x+threadIdx.x;  
//   	printf("In child\n");
	if(tid>=50) return;
	int I, j;
   	I=0;
    int len = pkts[I].len;
//printf("-------------1---------------\n");
    struct aho_state *st_arr = NULL;
	int dfa_id = pkts[I].dfa_id[tid]; 
	int state = ips_state->_state[tid];
	st_arr=dfa_arr[dfa_id].root; 
	ips_state->_state[tid]=(state >= dfa_arr[dfa_id].num_used_states)?0:ips_state->_state[tid];
//printf("-------------2---------------\n");	
	for(j = 0; j < len; j++) {
	
		int count = st_arr[state].output.count;
		ips_state->_alert[tid] =(count != 0||ips_state->_alert[tid]==true)?true:ips_state->_alert[tid];
		int inp = pkts[I].content[j];
		state = st_arr[state].G[inp]; 
	}
//printf("-------------3---------------\n");	
	ips_state->_state[tid] = state;
   	
}  

__device__ void process_batch(const struct aho_dfa *dfa_arr,    
   char *pkts, struct ips_flow_state *ips_state) {
    int  j;
    
   
    int len = pkt_len(pkts);
    struct aho_state *st_arr = NULL;
        
    
    

   	for(int times=0;times<DFA_NUM;times++){
   	
   	    int dfa_id = ips_state->_dfa_id[times]; 
   	    int state = ips_state->_state[times];
   	    st_arr=dfa_arr[dfa_id].root; 
   	    ips_state->_state[times]=(state >= dfa_arr[dfa_id].num_used_states)?0:ips_state->_state[times];
   		for(j = 0; j < len; j++) {
	
			int count = st_arr[state].output.count;
			ips_state->_alert[times] =(count != 0||ips_state->_alert[times]==true)?true:ips_state->_alert[times];
			int inp = pkts[j];
			state = st_arr[state].G[inp]; 
		}
	ips_state->_state[times] = state;
   	}

	//childKernel<<<1,64>>>(dfa_arr,pkts,ips_state);
   
}

__device__ void ids_func(struct aho_ctrl_blk *cb,struct ips_flow_state *state)
{
    int i;
 
    struct aho_dfa *dfa_arr = cb->dfa_arr;
    struct aho_pkt *pkts = cb->pkts;
    int num_pkts = cb->num_pkts;

    for(i = 0; i < num_pkts; i += BATCH_SIZE) {
        process_batch(dfa_arr, (char*)pkts[i].content, state);

    }
}

__device__ void parse_pkt(char *pkt, struct ips_flow_state *state, struct aho_pkt *aho_pkt){
	

    uint32_t len = pkt_len(pkt);
    aho_pkt->content=(uint8_t *)pkt;
    aho_pkt->dfa_id = state->_dfa_id;
    aho_pkt->len = len;
}

__device__ void ips_detect(char *rte_pkt, struct ips_flow_state *state, struct gpu_IPS *ips){
	
    struct aho_pkt* pkts = (struct aho_pkt *)malloc(sizeof(struct aho_pkt));
    parse_pkt(rte_pkt, state, pkts);
    struct aho_ctrl_blk worker_cb;

    worker_cb.stats = ips->stats;
    worker_cb.tot_threads = 1;
    worker_cb.tid = 0;
    worker_cb.dfa_arr = ips->dfa_arr;
    worker_cb.pkts = pkts;
    worker_cb.num_pkts = 1;

    ids_func(&worker_cb, state);

    free(pkts->content);
    free(pkts);
}

#endif