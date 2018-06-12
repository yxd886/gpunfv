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

//#include "../include/packet_parser.cuh"
#include "../../nf/aho-corasick/fpp.h"
#include "../../nf/aho-corasick/aho.hh"

// #define MAX_MATCH 8192
// #define MAX_PKT_SIZE 64
#define DFA_NUM 200

class ips_flow_state{
public:
    uint16_t _state[DFA_NUM];
    int _dfa_id[DFA_NUM];
    bool _alert[DFA_NUM];

    __device__ ips_flow_state& operator=(const ips_flow_state& s) {
        for(int i = 0; i < DFA_NUM; i++) {
            _state[i] = s._state[i];
            _dfa_id[i] = s._dfa_id[i];
            _alert[i] = s._alert[i];
        }

        return *this;
    }
};

struct gpu_IPS{ 
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
};

class IPS {
public:
    __device__ inline static void nf_logic(void *pkt, ips_flow_state *state, aho_dfa *info) {
        process_batch((char *)pkt, state, info);
    }

    __device__ inline static void process_batch(char *pkt, ips_flow_state *ips_state, const aho_dfa *dfa_arr) {
        int  j;

        uint16_t len = *(size_t*)pkt;
        char* content = pkt+sizeof(size_t);
        struct aho_state *st_arr = NULL;

        //#pragma unroll (5)
        for(int times=0;times<DFA_NUM;times++){
            int dfa_id = ips_state->_dfa_id[times]; 
            int state = ips_state->_state[times];
            st_arr=dfa_arr[dfa_id].root; 
            state=(state >= dfa_arr[dfa_id].num_used_states)?0:state;
            for(j = 0; j < len; j++) {
                int count = st_arr[state].output.count;
                ips_state->_alert[times] =(count != 0||ips_state->_alert[times]==true)?true:ips_state->_alert[times];
                int inp = content[j];
                state = st_arr[state].G[inp]; 
            }
            ips_state->_state[times] = state;
        }

    }

};

#endif