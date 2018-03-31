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
#include "../seastar/nf/aho-corasick/fpp.h"
#include "../seastar/nf/aho-corasick/aho.hh"

#define MAX_MATCH 8192

struct ips_flow_state{
    uint8_t tag;
    uint32_t _state;
    uint32_t _dfa_id;
    bool _alert;
};

struct mp_list_t {
    int num_match;
    uint16_t ptrn_id[MAX_MATCH];
};

struct gpu_IPS{ 
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
};

__device__ void process_batch(const struct aho_dfa *dfa_arr,    
   const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_flow_state *ips_state) {
    int I, j;
    
   // printf("in process_batch\n");

    for(I = 0; I < BATCH_SIZE; I++) {
    		//printf("------------------0-----------------\n");
        int dfa_id = pkts[I].dfa_id;
       //printf("------------------1-----------------\n");
//printf("dfa_id:%d\n",dfa_id);
        
        int len = pkts[I].len;
    //printf("------------------2-----------------\n");
        struct aho_state *st_arr = NULL;
        st_arr=dfa_arr[dfa_id].root;
//printf("------------------3-----------------\n");
      
        int state = ips_state->_state;
//printf("------------------4-----------------\n");
//printf("state: %d\n",state);
//printf("dfa_arr[dfa_id].num_used_states: %d\n",dfa_arr[dfa_id].num_used_states);

        if(state >= dfa_arr[dfa_id].num_used_states){
            ips_state->_alert=false;
            ips_state->_state=state;
            return ;
        }
//printf("------------------5-----------------\n");

       for(j = 0; j < len; j++) {
//printf("------------------6-----------------\n");
            int count = st_arr[state].output.count;
//printf("------------------7-----------------\n");

            if(count != 0) {
                /* This state matches some patterns: copy the pattern IDs
                 *  to the output */
                int offset = mp_list[I].num_match;
                memcpy(&mp_list[I].ptrn_id[offset], st_arr[state].out_arr, count * sizeof(uint16_t));
                mp_list[I].num_match += count;
                ips_state->_alert = true;
                ips_state->_state = state;
                return ;
            }
//printf("------------------8-----------------\n");	
           int inp = pkts[I].content[j];
            state = st_arr[state].G[inp];
        
       }
//printf("------------------9----------------\n");

       ips_state->_state = state;
   }
}

__device__ void ids_func(struct aho_ctrl_blk *cb,struct ips_flow_state *state)
{
    int i, j;
   // printf("in ids_func\n");
    

    struct aho_dfa *dfa_arr = cb->dfa_arr;
    struct aho_pkt *pkts = cb->pkts;
    int num_pkts = cb->num_pkts;

    /* Per-batch matched patterns */
    struct mp_list_t mp_list[BATCH_SIZE];
    for(i = 0; i < BATCH_SIZE; i++) {
        mp_list[i].num_match = 0;
    }

    /* Being paranoid about GCC optimization: ensure that the memcpys in
     *  process_batch functions don't get optimized out */


    //int tot_proc = 0;     /* How many packets did we actually match ? */
    //int tot_success = 0;  /* Packets that matched a DFA state */
    // tot_bytes = 0;       /* Total bytes matched through DFAs */

    for(i = 0; i < num_pkts; i += BATCH_SIZE) {
        process_batch(dfa_arr, &pkts[i], mp_list, state);

        for(j = 0; j < BATCH_SIZE; j++) {
            int num_match = mp_list[j].num_match;
            //assert(num_match < MAX_MATCH);

            mp_list[j].num_match = 0;
        }
    }
}

__device__ void parse_pkt(char *pkt, struct ips_flow_state *state, struct aho_pkt *aho_pkt){
	
    //printf("in parse_pkt\n");
    uint32_t len = pkt_len(pkt);
 //printf("parse_pkt(): state->_dfa_id = %d\n", state->_dfa_id);

    aho_pkt->content = (uint8_t *)malloc(len);
    memcpy(aho_pkt->content, pkt, len);
    aho_pkt->dfa_id = state->_dfa_id;
    aho_pkt->len = len;
}

__device__ void ips_detect(char *rte_pkt, struct ips_flow_state *state, struct gpu_IPS *ips){
	

    //printf("in ips_detect\n");
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