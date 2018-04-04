#pragma once
#ifndef IPS_H_
#define IPS_H_


#include "mica/util/hash.h"

#include "nf/nf_common.h"
#include <vector>
#include <iostream>
#include "nf/aho-corasick/fpp.h"
#include "nf/aho-corasick/aho.h"
#define MAX_MATCH 8192
#include <stdlib.h>
#include <time.h>
using namespace seastar;






/* A list of patterns matched by a packet */
struct mp_list_t {
	int num_match;
	uint16_t ptrn_id[MAX_MATCH];
};

/* Plain old API-call batching */
void process_batch(const struct aho_dfa *dfa_arr,
	const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_state* ips_state)
{
	int I, j;

	for(I = 0; I < BATCH_SIZE; I++) {
		int dfa_id = pkts[I].dfa_id;
		int len = pkts[I].len;
		struct aho_state *st_arr = dfa_arr[dfa_id].root;

		int state = ips_state->_state;
	//	if(state>=dfa_arr[dfa_id].num_used_states){
	//		state=0;
	//	}


		for(j = 0; j < len; j++) {
			int count = st_arr[state].output.count;

			if(count != 0) {
				/* This state matches some patterns: copy the pattern IDs
				  *  to the output */
				int offset = mp_list[I].num_match;
				memcpy(&mp_list[I].ptrn_id[offset],
					st_arr[state].out_arr, count * sizeof(uint16_t));
				mp_list[I].num_match += count;
				ips_state->_alert=true;
				ips_state->_state=state;
				return;

			}
			int inp = pkts[I].content[j];
			state = st_arr[state].G[inp];
		}
		ips_state->_state=state;
	}


}

bool state_updated(struct ips_state* old_,struct ips_state* new_){
	if(DEBUG) printf("old_->_alert:%d new_->_alert:%d old_->_dfa_id:%d new_->_dfa_id:%d old_->_state:%d new_->_state:%d\n",old_->_alert,new_->_alert,old_->_dfa_id,new_->_dfa_id,old_->_state,new_->_state);
	if(old_->_alert==new_->_alert&&old_->_dfa_id==new_->_dfa_id&&old_->_state==new_->_state){
		return false;
	}
	return true;
}

void ids_func(struct aho_ctrl_blk *cb,struct ips_state* state)
{
	int i, j;



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


	//int tot_proc = 0;		/* How many packets did we actually match ? */
	//int tot_success = 0;	/* Packets that matched a DFA state */
	// tot_bytes = 0;		/* Total bytes matched through DFAs */

	for(i = 0; i < num_pkts; i += BATCH_SIZE) {
		process_batch(dfa_arr, &pkts[i], mp_list,state);

		for(j = 0; j < BATCH_SIZE; j++) {
			int num_match = mp_list[j].num_match;
			assert(num_match < MAX_MATCH);


			mp_list[j].num_match = 0;
		}
	}



}

void parse_pkt(net::packet *rte_pkt, struct ips_state* state,struct aho_pkt*  aho_pkt){

	aho_pkt->content=(uint8_t*)malloc(rte_pkt->len());
	memcpy(aho_pkt->content,rte_pkt->get_header(0,sizeof(char)),rte_pkt->len());
	aho_pkt->dfa_id=state->_dfa_id;
	aho_pkt->len=rte_pkt->len();
}


class IPS{
public:
    IPS():
		_drop(false){



    		int num_patterns, i;

        	int num_threads = 1;
        	assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        	stats =(struct stat_t*)malloc(num_threads * sizeof(struct stat_t));
        	for(i = 0; i < num_threads; i++) {
        		stats[i].tput = 0;
        	}

        	struct aho_pattern *patterns;



        	/* Thread structures */
        	//pthread_t worker_threads[AHO_MAX_THREADS];


        	red_printf("State size = %lu\n", sizeof(struct aho_state));

        	/* Initialize the shared DFAs */
        	for(i = 0; i < AHO_MAX_DFA; i++) {
        		printf("Initializing DFA %d\n", i);
        		aho_init(&dfa_arr[i], i);
        	}

        	red_printf("Adding patterns to DFAs\n");
        	patterns = aho_get_patterns(AHO_PATTERN_FILE,
        		&num_patterns);

        	for(i = 0; i < num_patterns; i++) {
        		int dfa_id = patterns[i].dfa_id;
        		aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
        	}

        	red_printf("Building AC failure function\n");
        	for(i = 0; i < AHO_MAX_DFA; i++) {
        		aho_build_ff(&dfa_arr[i]);
        		aho_preprocess_dfa(&dfa_arr[i]);
        	}
    }





   future<> init_automataState(struct ips_state* state){
    	srand((unsigned)time(NULL));
    	state->_state=0;
    	state->_alert=false;
    	state->_dfa_id=rand()%AHO_MAX_DFA;
    	return make_ready_future<>();
    }
    void ips_detect(net::packet *rte_pkt, struct ips_state* state){

    	struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));
    	parse_pkt(rte_pkt, state,pkts);
       	struct aho_ctrl_blk worker_cb;



		worker_cb.stats = stats;
		worker_cb.tot_threads = 1;
		worker_cb.tid = 0;
		worker_cb.dfa_arr = dfa_arr;
		worker_cb.pkts = pkts;
		worker_cb.num_pkts = 1;

		ids_func(&worker_cb,state);


    }


    void init_ip_state(struct ips_state* state){
        state->_alert=false;
        state->_dfa_id=0;
        state->_state=0;
    }


	future<> process_packet(net::packet* rte_pkt,per_core_objs<mica_client> all_objs){


		if(DEBUG==1) printf("processing ips on core:%d\n",rte_lcore_id());

		net::ip_hdr *iphdr;
		net::tcp_hdr *tcp;
	    _drop=false;
	    iphdr =rte_pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));

	    if (iphdr->ip_proto!=(uint8_t)net::ip_protocol_num::tcp){
		    //drop
	    	if(DEBUG==1) printf("not tcp pkt\n");
	        _drop=true;
	        return make_ready_future<>();
	    }else{

	    	tcp = (net::tcp_hdr *)((unsigned char *)iphdr +sizeof(net::ip_hdr));
	    	struct ips_state state;
	    	init_ip_state(&state);
	    	struct fivetuple tuple(iphdr->src_ip.ip,iphdr->dst_ip.ip,tcp->src_port,tcp->dst_port,iphdr->ip_proto);

	       // printf("src_addr:%d ,iphdr->dst_addr:%d tcp->src_port:%d tcp->dst_port:%d\n ",iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port);


            //generate key based on five-tuples
	        char* key = reinterpret_cast<char*>(&tuple);
            extendable_buffer key_buf;
            key_buf.fill_data(key);

            extendable_buffer val_buf;
            val_buf.fill_data(state);

	    	  if(tcp->f_syn==1){ //is A tcp syn

	    		    return init_automataState(&state).then([&]{



                        return all_objs.local_obj().query(Operation::kSet,
                                sizeof(key), key_buf.get_temp_buffer(),
                                sizeof(state), val_buf.get_temp_buffer()).then([](mica_response response){
                            assert(response.get_key_len() == 0);
                            assert(response.get_val_len() == 0);
                            assert(response.get_result() == Result::kSuccess);
                            return make_ready_future<>();
                        });

	    		    });

	    	  }else{


	  	        return all_objs.local_obj().query(Operation::kGet,
                        sizeof(key), key_buf.get_temp_buffer(),
                        0, temporary_buffer<char>()).then([&](mica_response response){

	                if(response.get_result() == Result::kNotFound){


	                    return init_automataState(&state).then([&]{


	                            return all_objs.local_obj().query(Operation::kSet,
	                                    sizeof(key), key_buf.get_temp_buffer(),
	                                    sizeof(state), val_buf.get_temp_buffer()).then([&](mica_response response){
	                                assert(response.get_key_len() == 0);
	                                assert(response.get_val_len() == 0);
	                                assert(response.get_result() == Result::kSuccess);
	                                return make_ready_future<>();
	                            });

	                    });

	                }else{

	                    memcpy(&state,&(response.get_value<struct ips_state>()),sizeof(state));
	                    if(DEBUG==1)  printf("RECEIVE: alert: %d state: %d, dfa_id:%d\n",state._alert,state._state, state._dfa_id);
	                    struct ips_state old;
	                    init_ip_state(&old);
	                    memcpy(&old,&state,sizeof(state));
	                    ips_detect(rte_pkt,&state);
	                    if(state_updated(&old,&state)){
	                        extendable_buffer set_val_buf;
	                        set_val_buf.fill_data(state);
	                        all_objs.local_obj().query(Operation::kSet,
	                                                                sizeof(key), key_buf.get_temp_buffer(),
	                                                                sizeof(state), set_val_buf.get_temp_buffer()).then([]( mica_response response){
                                assert(response.get_key_len() == 0);
                                assert(response.get_val_len() == 0);
                                assert(response.get_result() == Result::kSuccess);
	                        });
	                    }


	                    if(state._alert){
	                        _drop=true;
	                        return make_ready_future<>();
	                    }
	                    return make_ready_future<>();
	                }



	  	        });



	    	  }

	    }


    }

	bool _drop;
	struct aho_dfa dfa_arr[AHO_MAX_DFA];
	struct stat_t *stats;


};


#endif
