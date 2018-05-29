/*
 * ips.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef IPS_HH
#define IPS_HH

#include "../../nf/aho-corasick/fpp.h"
#include "../../nf/aho-corasick/aho.h"
#include "../include/packet_parser.hh"


#define DFA_NUM 50

struct ips_flow_state {
    uint16_t _state[1];
    int _dfa_id[1];
    bool _alert[1];

};

class IPS {
public:
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
    IPS *info_for_gpu;

    inline void init_automataState(struct ips_flow_state& state){
        for(int i = 0; i < DFA_NUM; i++){
            srand((unsigned)time(NULL));
            state._state[i] = 0;
            state._alert[i] = false;
            state._dfa_id[i] = rand() % AHO_MAX_DFA;
        }
    }

    inline void nf_logic(void *pkt, struct ips_flow_state* state) {   
        ips_detect(pkt, state);
    }

    IPS(){
        int num_patterns, i;
        int num_threads = 1;
        assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        gpu_malloc((void**)(&info_for_gpu), sizeof(IPS));

        struct stat_t *gpu_stats;
        stats =(struct stat_t *)malloc(num_threads * sizeof(struct stat_t));
        assert(stats!=NULL);
        gpu_malloc((void**)(&gpu_stats), num_threads * sizeof(struct stat_t));

        for(i = 0; i < num_threads; i++) {
            stats[i].tput = 0;
        }

        struct aho_pattern *patterns;
        /* Thread structures */
        //pthread_t worker_threads[AHO_MAX_THREADS];

        red_printf("State size = %lu\n", sizeof(struct aho_state));

        /* Initialize the shared DFAs */
        for(i = 0; i < AHO_MAX_DFA; i++) {
            //printf("Initializing DFA %d\n", i);
            //printf("i=%d\n",i);
            aho_init(&dfa_arr[i], i);
        }

        red_printf("Adding patterns to DFAs\n");
        patterns = aho_get_patterns(AHO_PATTERN_FILE, &num_patterns);

        for(i = 0; i < num_patterns; i++) {
            int dfa_id = patterns[i].dfa_id;
            aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
        }

        red_printf("Building AC failure function\n");
        for(i = 0; i < AHO_MAX_DFA; i++) {
            aho_build_ff(&dfa_arr[i]);
            aho_preprocess_dfa(&dfa_arr[i]);
        }

        gpu_memcpy_async_h2d(info_for_gpu, this, sizeof(IPS));

        for(i = 0; i < AHO_MAX_DFA; i++) {
            struct aho_state* gpu_root;
            int offset = (char *)&dfa_arr[i].root - (char *)this;
            char *des_addr = (char *)info_for_gpu + offset;
            //printf("i = :%d, max = %d\n",i,AHO_MAX_DFA);
            gpu_malloc((void**)(&gpu_root), AHO_MAX_STATES * sizeof(struct aho_state));

            gpu_memcpy_async_h2d(gpu_root, dfa_arr[i].root, AHO_MAX_STATES * sizeof(struct aho_state));
            gpu_memcpy_async_h2d(des_addr, &gpu_root, sizeof(struct aho_state *));
        }

        gpu_memcpy_async_h2d(gpu_stats, stats, num_threads * sizeof(struct stat_t));
    }

    ~IPS(){
        for(int i = 0; i < AHO_MAX_DFA; i++) {
            //gpu_mem_unmap(dfa_arr[i].root);
            free(dfa_arr[i].root);
        }
        free(stats);
    }
    
    struct mp_list_t {
        int num_match;
        uint16_t ptrn_id[MAX_MATCH];
    };

    void parse_pkt(void *pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){
        uint16_t len = packetParser::get_size(pkt);

       aho_pkt->content=(uint8_t*)malloc(len);
       memcpy(aho_pkt->content, pkt, len-1);
       aho_pkt->dfa_id=state->_dfa_id;
       aho_pkt->len = len;

   }

   void process_batch(const struct aho_dfa *dfa_arr,
       const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_flow_state* ips_state) {
        int I, j;

        for(I = 0; I < BATCH_SIZE; I++) {
            int len = pkts[I].len;


            int states[DFA_NUM];
            int dfa_ids[DFA_NUM];
            struct aho_state *st_arrs[DFA_NUM];
            for(int i = 0; i<DFA_NUM;i++){
                states[i]= ips_state->_state[i];
                dfa_ids[i] = pkts[I].dfa_id[i];
                //__builtin_prefetch(&dfa_arr[dfa_ids[i]]);

            }
            for(int i = 0; i<DFA_NUM; i++){
                st_arrs[i] = dfa_arr[dfa_ids[i]].root;
                //__builtin_prefetch(st_arrs[i]);
                //__builtin_prefetch(&st_arrs[i][states[i]]);
            }

            //__builtin_prefetch(pkts[I].content);

            for(int times=0;times<DFA_NUM;times++){

                //int state = ips_state->_state[times];
                //int dfa_id = pkts[I].dfa_id[times];
                //struct aho_state *st_arr = dfa_arr[dfa_id].root;
                if(states[times]>=dfa_arr[dfa_ids[times]].num_used_states){
                     ips_state->_alert[times]=false;
                     ips_state->_state[times]=0;
                }

                for(j = 0; j < len; j++) {
                    int count = st_arrs[times][states[times]].output.count;

                    if(count != 0) {
                        /* This state matches some patterns: copy the pattern IDs
                        *  to the output */
                        int offset = mp_list[I].num_match;
                        mp_list[I].num_match ++;
                        ips_state->_alert[times]=true;
                        ips_state->_state[times]=0;

                    }

                    int inp = pkts[I].content[j];
                    states[times] = st_arrs[times][states[times]].G[inp];
                }
                //std::cout<<"      after for loop"<<std::endl;
                ips_state->_state[times]=states[times];
            }
        }
    }


    void ids_func(struct aho_ctrl_blk *cb,struct ips_flow_state* state) {
        int i, j;
        struct aho_dfa *dfa_arr = cb->dfa_arr;
        struct aho_pkt *pkts = cb->pkts;
        int num_pkts = cb->num_pkts;

        /* Per-batch matched patterns */
        struct mp_list_t mp_list[BATCH_SIZE];
        for(i = 0; i < BATCH_SIZE; i++) {
            mp_list[i].num_match = 0;
        }

        for(i = 0; i < num_pkts; i += BATCH_SIZE) {
            //std::cout<<"    before process_batch"<<std::endl;
            process_batch(dfa_arr, &pkts[i], mp_list,state);
            //std::cout<<"    after process_batch"<<std::endl;
            for(j = 0; j < BATCH_SIZE; j++) {
                int num_match = mp_list[j].num_match;
                assert(num_match < MAX_MATCH);
                mp_list[j].num_match = 0;
            }
        }
   }

   void ips_detect(void *pkt, struct ips_flow_state* state){
        struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));

        parse_pkt(pkt, state,pkts);

        struct aho_ctrl_blk worker_cb;
        worker_cb.stats = this->stats;
        worker_cb.tot_threads = 1;
        worker_cb.tid = 0;
        worker_cb.dfa_arr = this->dfa_arr;
        worker_cb.pkts = pkts;
        worker_cb.num_pkts = 1;
        //std::cout<<"  before ids_func"<<std::endl;
        ids_func(&worker_cb,state);
        //std::cout<<"  after ids_func"<<std::endl;
        free(pkts->content);
        free(pkts);
   }

};

#endif /* IPS_HH */
