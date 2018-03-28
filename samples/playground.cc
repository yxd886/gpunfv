/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 */

#include "netstar/preprocessor/tcp_ppr.hh"

#include "core/reactor.hh"
#include "core/app-template.hh"
#include "core/sleep.hh"

#include "netstar/port_manager.hh"
#include "netstar/stack/stack_manager.hh"
#include "netstar/hookpoint/hook_manager.hh"
#include "netstar/mica/mica_client.hh"

#include "netstar/asyncflow/sd_async_flow.hh"
#include "netstar/asyncflow/async_flow.hh"

#include "netstar/preprocessor/udp_ppr.hh"


#include "playground.hh"

#include <vector>
#include <iostream>
#include <algorithm>
#include "nf/aho-corasick/fpp.h"
#include "nf/aho-corasick/aho.h"
#define MAX_MATCH 8192
#include <stdlib.h>
#include <time.h>

#include <unordered_map>
#define GPU_BATCH_SIZE 2000

#define COMPUTE_RATIO 50

using namespace seastar;
using namespace netstar;
using namespace std::chrono_literals;

extern std::vector<struct rte_mempool*> netstar_pools;

struct fake_val {
    uint64_t v[3];
};


class IPS{
public:
    IPS(){

        int num_patterns, i;

        int num_threads = 1;
        assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        stats =(struct stat_t*)malloc(num_threads * sizeof(struct stat_t));

        //gpu map
        gpu_mem_map(stats,num_threads * sizeof(struct stat_t));

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
            aho_init(&dfa_arr[i], i);
            gpu_mem_map(dfa_arr[i].root,AHO_MAX_STATES * sizeof(struct aho_state));
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

        // Map ips object

        gpu_mem_map(this, sizeof(IPS));
    }
    ~IPS(){

        for(int i = 0; i < AHO_MAX_DFA; i++) {

            gpu_mem_unmap(dfa_arr[i].root);
            free(dfa_arr[i].root);
        }



        gpu_mem_unmap(stats);
        gpu_mem_unmap(this);
        free(stats);
    }
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;

};





class forwarder;
distributed<forwarder> forwarders;

class forwarder {
    sd_async_flow_manager<tcp_ppr> _tcp_forward;
    sd_async_flow_manager<udp_ppr> _udp_forward;
    mica_client& _mc;
public:
    forwarder() : _mc(std::ref(mica_manager::get().mc())),_pkt_counter(0){
        hook_manager::get().hOok(0).send_to_sdaf_manager(_tcp_forward);
        hook_manager::get().hOok(0).receive_from_sdaf_manager(_tcp_forward);

        hook_manager::get().hOok(0).send_to_sdaf_manager(_udp_forward);
        hook_manager::get().hOok(0).receive_from_sdaf_manager(_udp_forward);
    }

    future<> stop() {
        return make_ready_future<>();
    }

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

    struct query_key {
        uint64_t v1;
        uint64_t v2;
    };

    class flow_operator {


    public:
        sd_async_flow<udp_ppr> _ac;
        forwarder& _f;
        ips_flow_state _fs;
        std::vector<netstar::rte_packet> packets[2];
        bool _initialized;


        flow_operator(sd_async_flow<udp_ppr> ac, forwarder& f)
            : _ac(std::move(ac))
            , _f(f)
            ,_initialized(false){}
        //flow_operator(const flow_operator& other) = delete;
        /*flow_operator(flow_operator&& other) noexcept
            : _ac(std::move(other._ac)),_f(other._f),_fs(other._fs) ,_initialized(other._initialized){

            for(unsigned int i=0;i<other.packets[current_idx].size();i++){
                packets[current_idx].push_back(std::move(other.packets[current_idx][i]));
            }
        }
        ~flow_operator(){
            std::cout<<"packets[current_idx].size:"<<packets[current_idx].size()<<std::endl;
            std::cout<<"deconstruction:"<<std::endl;

            assert(packets[current_idx].size()<100);


        }*/


        void events_registration() {
            _ac.register_events(udp_events::pkt_in);
        }

        void post_process(){

            _f._pkt_counter-=packets[_f._batch.current_idx].size();
            assert(_f._pkt_counter>=0);
            process_pkts(_f._batch.current_idx);
            std::vector<flow_operator*>::iterator it;
            for(it=_f._batch._flows[_f._batch.current_idx].begin();it!=_f._batch._flows[_f._batch.current_idx].end();it++){
                if(*it==this){
                    _f._batch._flows[_f._batch.current_idx].erase(it);
                    break;
                }
            }


        }
        void process_pkt(netstar::rte_packet* pkt, ips_flow_state* fs){


            ips_flow_state old;
            old._alert=fs->_alert;
            old._dfa_id=fs->_dfa_id;
            old._state=fs->_state;
            old.tag=fs->tag;
            //std::cout<<"before ips_detect"<<std::endl;
            ips_detect(pkt,fs);
            //std::cout<<"after ips_detect"<<std::endl;
            auto state_changed=state_updated(&old,fs);
            if(state_changed) {
                auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                _f._mc.query(Operation::kSet, mica_key(key),
                        mica_value(*fs)).then([this](mica_response response){
                    return make_ready_future<>();
                });
            }

        }

        void forward_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){

                //std::cout<<"begin to send pkt"<<std::endl;
                _ac.internal_send(std::move(packets[index][i]));
                //std::cout<<"finish sending pkt"<<std::endl;
            }
            packets[index].clear();
            assert(packets[index].size()==0);
        }
        void process_pkts(uint64_t index){
            //std::cout<<"packets[index].size:"<<packets[index].size()<<std::endl;
            for(unsigned int i=0;i<packets[index].size();i++){
                //std::cout<<"packets[current_idx].size:"<<packets[index].size()<<std::endl;
                //std::cout<<"process "<<i<<" packets[index]"<<std::endl;
                //process_pkt(&packets[current_idx][i],&_fs);

            }
            forward_pkts(index);

        }
        future<>update_state(uint64_t index){
            if(packets[index].empty()){   //if it is the first packets[current_idx] of this flow in this batch
                if(_initialized){    //if it has already processed previous batch, then the state is newer than remote, so update to remote.
                    auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                    return _f._mc.query(Operation::kSet, mica_key(key),
                            mica_value(_fs)).then([](mica_response response){
                        return make_ready_future<>();
                    });
                }else{              //if it is just initialized, it need get the flow state from the remote server.
                    _initialized=true;
                    auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                    return _f._mc.query(Operation::kGet, mica_key(key),
                            mica_value(0, temporary_buffer<char>())).then([this](mica_response response){
                        if(response.get_result() == Result::kNotFound) {
                            init_automataState(_fs);
                            auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                            return _f._mc.query(Operation::kSet, mica_key(key),
                                    mica_value(_fs)).then([this](mica_response response){
                                return make_ready_future<>();
                            });
                        }
                        else {
                            _fs = response.get_value<ips_flow_state>();
                            return make_ready_future<>();

                        }

                    });

                }
            }else{
                return make_ready_future<>();
            }

            //return make_ready_future<>();
        }

        future<> run_ips() {
            return _ac.run_async_loop([this](){
                if(_ac.cur_event().on_close_event()) {
                    post_process();
                    return make_ready_future<af_action>(af_action::close_forward);
                }
                //uint64_t test_len=mbufs_per_queue_tx*inline_mbuf_size+mbuf_cache_size+sizeof(struct rte_pktmbuf_pool_private);

                //printf("pkt: %p, RX_ad: %p, TX_ad: %p, len: %ld, end_RX: %p, end_TX: %p",_ac.cur_packet().get_header<net::eth_hdr>(0),netstar_pools[1],netstar_pools[0],test_len,test_len+(char*)netstar_pools[1],test_len+(char*)netstar_pools[0]);
                //assert(((char*)_ac.cur_packet().get_header<net::eth_hdr>(0)>=(char*)netstar_pools[1]&&(char*)_ac.cur_packet().get_header<net::eth_hdr>(0)<=test_len+(char*)netstar_pools[1])||((char*)_ac.cur_packet().get_header<net::eth_hdr>(0)>=(char*)netstar_pools[0]&&(char*)_ac.cur_packet().get_header<net::eth_hdr>(0)<=test_len+(char*)netstar_pools[0]));

                if(_f._pkt_counter>=GPU_BATCH_SIZE&&_f._batch.need_process==true){

                    return make_ready_future<af_action>(af_action::drop);

                 }

                //std::cout<<"pkt_num:"<<_f._pkt_counter<<std::endl;

                return update_state(_f._batch.current_idx)                       //update the flow state when receive the first pkt of this flow in this batch.
                        .then([this](){
                    if(packets[_f._batch.current_idx].empty()){
                        _f._batch._flows[_f._batch.current_idx].push_back(this);
                    }

                    _f._pkt_counter++;
                    packets[_f._batch.current_idx].push_back(std::move(_ac.cur_packet()));

                    if(_f._pkt_counter>=GPU_BATCH_SIZE&&_f._batch.need_process==false){
                         _f._batch.need_process=true;
                         _f._pkt_counter=0;
                         _f._batch.current_idx=!_f._batch.current_idx;


                     }
                    if(_f._batch.need_process==true&&_f._batch.processing==false){
                        //reach batch size schedule
                        _f._batch.processing=true;
                        //std::cout<<"schedule_task"<<std::endl;
                        return  _f._batch.schedule_task(!_f._batch.current_idx)
                                .then([this](){
                            _f._batch.need_process=false;
                            _f._batch.processing=false;
                            return make_ready_future<af_action>(af_action::hold);
                        });


                    }else{
                        return make_ready_future<af_action>(af_action::hold);
                    }
                    //return make_ready_future<af_action>(af_action::forward);


                });

            });
        }

       void init_automataState(struct ips_flow_state& state){
             srand((unsigned)time(NULL));
             state._state=0;
             state._alert=false;
             state._dfa_id=rand()%AHO_MAX_DFA;
             //std::cout<<"init_automataState_dfa_id:"<<state._dfa_id<<std::endl;
         }
       void parse_pkt(netstar::rte_packet *rte_pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){

           aho_pkt->content=(uint8_t*)malloc(rte_pkt->len());
           //std::cout<<"    rte_pkt->len():"<<rte_pkt->len()<<std::endl;
           memcpy(aho_pkt->content,reinterpret_cast<uint8_t*>(rte_pkt->get_header(0,sizeof(char))),rte_pkt->len()-1);
           aho_pkt->dfa_id=state->_dfa_id;
           aho_pkt->len=rte_pkt->len();
           //std::cout<<"    aho_pkt->len:"<<rte_pkt->len()<<std::endl;
       }
       bool state_updated(struct ips_flow_state* old_,struct ips_flow_state* new_){
           if(old_->_alert==new_->_alert&&old_->_dfa_id==new_->_dfa_id&&old_->_state==new_->_state){
               return false;
           }
           return true;
       }

       void process_batch(const struct aho_dfa *dfa_arr,
           const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_flow_state* ips_state)
       {
           int I, j;

           for(I = 0; I < BATCH_SIZE; I++) {
               int dfa_id = pkts[I].dfa_id;
               //std::cout<<"      dfa_id:"<<dfa_id<<std::endl;
               int len = pkts[I].len;
               //std::cout<<"      len:"<<len<<std::endl;
               struct aho_state *st_arr = dfa_arr[dfa_id].root;

               int state = ips_state->_state;
             if(state>=dfa_arr[dfa_id].num_used_states){
                 ips_state->_alert=false;
                 ips_state->_state=state;
                 return;
             }
               //std::cout<<"      state:"<<state<<std::endl;
               //std::cout<<"      before for loop"<<std::endl;
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
               //std::cout<<"      after for loop"<<std::endl;
               ips_state->_state=state;
           }


       }
       void ids_func(struct aho_ctrl_blk *cb,struct ips_flow_state* state)
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


           //int tot_proc = 0;     /* How many packets[_f._batch.current_idx] did we actually match ? */
           //int tot_success = 0;  /* packets[_f._batch.current_idx] that matched a DFA state */
           // tot_bytes = 0;       /* Total bytes matched through DFAs */

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
       void ips_detect(netstar::rte_packet *rte_pkt, struct ips_flow_state* state){

           //cudaError_t err=cudaSuccess;
           struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));
           //err=cudaHostRegister(rte_pkt,sizeof(netstar::rte_packet),cudaHostRegisterPortable);
           //if(err==cudaSuccess){
           //    printf("cudaHostRegister success!\n");
           //}else if(err==cudaErrorHostMemoryAlreadyRegistered){
              // printf("cudaErrorHostMemoryAlreadyRegistered!\n");
           //}else{
            //   printf("cudaHostRegister fail!\n");
           //}
           //std::cout<<"  before parse_pkt"<<std::endl;
           parse_pkt(rte_pkt, state,pkts);
           //std::cout<<"  after parse_pkt"<<std::endl;
           struct aho_ctrl_blk worker_cb;
           worker_cb.stats = _f.ips.stats;
           worker_cb.tot_threads = 1;
           worker_cb.tid = 0;
           worker_cb.dfa_arr = _f.ips.dfa_arr;
           worker_cb.pkts = pkts;
           worker_cb.num_pkts = 1;
           //std::cout<<"  before ids_func"<<std::endl;
           ids_func(&worker_cb,state);
           //std::cout<<"  after ids_func"<<std::endl;
           free(pkts->content);
           free(pkts);

       }


        af_action forward_packet(ips_flow_state& fs) {
            if(!fs._alert) {
                return af_action::forward;
            }
            else {
                return af_action::drop;
            }
        }
    };


    static bool CompLess(const flow_operator* lhs, const flow_operator* rhs)
    {
        return lhs->packets[!lhs->_f._batch.current_idx].size() < rhs->packets[!lhs->_f._batch.current_idx].size();
    }
    class batch {
    public:
        //uint64_t active_flow_num;
        //std::unordered_map<char*,uint64_t> pkt_number;
        //std::unordered_map<char*,uint64_t> flow_index;
        //std::unordered_map<uint64_t,char*> index_flow;
        //char* all_pkts[GPU_BATCH_SIZE][GPU_BATCH_SIZE];
        //char* states[GPU_BATCH_SIZE];
        //char* gpu_pkts;
        //char* gpu_states;
        //uint64_t max_pktnumber;
        //uint64_t gpu_flow_num;
        std::vector<flow_operator*> _flows[2];
        char** gpu_pkts;
        char** gpu_states;
        bool need_process;
        bool processing;
        uint64_t current_idx;

        batch():gpu_pkts(nullptr),gpu_states(nullptr),need_process(false),processing(false),current_idx(0){

        }
        ~batch(){

        }



        future<> schedule_task(uint64_t index){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU
            //std::cout<<"flow_size:"<<_flows[index].size()<<std::endl;
            std::cout<<"schedule task"<<std::endl;
            for(unsigned int i=0;i<_flows[index].size();i=i+1){
                //std::cout<<_flows[index][i]->packets[index].size()<<" ";
            }
            //std::cout<<"end before sort"<<std::endl;
            sort(_flows[index].begin(),_flows[index].end(),CompLess);
            int partition=get_partition(index);
            assert(partition!=-1);
            int max_pkt_num_per_flow=_flows[index][partition]->packets[index].size();

            if(partition>0){


                int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(char*);
                int ngpu_states = partition * sizeof(char*);
                gpu_pkts = (char **)malloc(ngpu_pkts);
                gpu_states = (char **)malloc(ngpu_states);

                assert(gpu_pkts);
                assert(gpu_states);

                // Clear and map gpu_pkts and gpu_states
                memset(gpu_pkts, 0, ngpu_pkts);
                memset(gpu_states, 0, ngpu_states);
                //printf("gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);
                gpu_mem_map(gpu_pkts, ngpu_pkts);
                gpu_mem_map(gpu_states, ngpu_states);

                //std::cout<<"memory alloc finished"<<std::endl;
                for(int i = 0; i < partition; i++){
                    gpu_states[i] = reinterpret_cast<char*>(&(_flows[index][i]->_fs));
                    gpu_mem_map(gpu_states[i], sizeof(struct ips_flow_state));
                    //std::cout<<"assign gpu_states["<<i<<"]"<<std::endl;
                    for(int j = 0; j < (int)_flows[index][i]->packets[index].size(); j++){

                        gpu_pkts[i*max_pkt_num_per_flow+j]=reinterpret_cast<char*>(_flows[index][i]->packets[index][j].get_header<net::eth_hdr>(0));
                        //std::cout<<"assign gpu_pkts["<<i<<"]"<<"["<<j<<"]"<<std::endl;

                        // Map every packet
                        //gpu_mem_map(gpu_pkts[i*max_pkt_num_per_flow+j], _flows[index][i]->packets[index][j].len());
                    }
                }

                //printf("----gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);

                /////////////////////////////////////////////
                // Launch kernel


                gpu_launch((char **)gpu_pkts, (char **)gpu_states, (char *)&(_flows[0][index]->_f.ips), max_pkt_num_per_flow, partition);

            }
            //std::cout<<"   partition:"<<partition<<std::endl;

            //
            /////////////////////////////////////////////

            //std::cout<<"begin to process_pkts"<<std::endl;

            for(unsigned int i = partition; i < _flows[index].size(); i++){
                _flows[index][i]->process_pkts(index);
            }

            // Wait for GPU process
            if(partition>0){
                gpu_sync();


                // Unmap every packet
               /* for(int i = 0; i < partition; i++){
                    gpu_mem_unmap(gpu_states[i]);

                    for(int j = 0; j < (int)_flows[index][i]->packets[index].size(); j++){
                        gpu_mem_unmap(gpu_pkts[i * max_pkt_num_per_flow + j]);
                    }
                }*/
                // Unmap gpu_pkts and gpu_states
                gpu_mem_unmap(gpu_pkts);
                gpu_mem_unmap(gpu_states);

                // Forward GPU packets[current_idx]
                for(int i = 0; i < partition; i++){
                    _flows[index][i]->forward_pkts(index);
                }



                if(gpu_pkts){
                    free(gpu_pkts);
                }
                if(gpu_states){
                    free(gpu_states);
                }
            }
            _flows[index].clear();

            return make_ready_future<>();

            //std::cout<<"gpu_process_pkts finished"<<std::endl;

          /*  return seastar::do_with(std::vector<flow_operator*>(_flows), [this] (auto& obj) {
                    // obj is passed by reference to slow_op, and this is fine:
                _flows.clear();
                if(gpu_pkts){
                    free(gpu_pkts);
                }
                if(gpu_states){
                    free(gpu_states);
                }
                return seastar::do_with(seastar::semaphore(100), [& obj] (auto& limit) {
                    return seastar::do_for_each(boost::counting_iterator<int>(0),
                            boost::counting_iterator<int>((int)obj.size()), [&limit,& obj] (int i) {
                        std::cout<<"flows_size:"<<obj.size()<<std::endl;
                        return seastar::get_units(limit, 1).then([i,& obj] (auto units) {
                            auto key = query_key{obj[i]->_ac.get_flow_key_hash(), obj[i]->_ac.get_flow_key_hash()};
                            return obj[i]->_f._mc.query(Operation::kSet, mica_key(key),
                                    mica_value(obj[i]->_fs)).then([](mica_response response){
                                return make_ready_future<>();
                            }).finally([units = std::move(units)] {});
                        });
                    }).finally([&limit] {
                        return limit.wait(100);
                    });
                });
            });*/



        }
        uint64_t get_partition(uint64_t index){

            std::vector<float> processing_time;
            for(unsigned int i=0;i<_flows[index].size();i++){
                float cpu_time=0;
                float gpu_time=_flows[index][i]->packets[index].size();
                for(unsigned int j=i+1;j<_flows[index].size();j++){
                    cpu_time+=_flows[index][j]->packets[index].size();
                }
                processing_time.push_back(std::max(gpu_time,cpu_time/COMPUTE_RATIO));
            }


           // std::cout<<"packet num begin"<<std::endl;
           // for(unsigned int i=0;i<_flows[index].size();i++){
           //     std::cout<<_flows[index][i]->packets[index].size()<<" ";
           // }
           // std::cout<<"packet num end"<<std::endl;



          //  std::cout<<"processing time begin"<<std::endl;
          //  for(unsigned int i=0;i<processing_time.size();i++){
          //      std::cout<<processing_time[i]<<" ";
          //  }
          //  std::cout<<"processing time end"<<std::endl;


            std::vector<float>::iterator result = std::min_element(std::begin(processing_time), std::end(processing_time));
            //std::cout<<"    min_processing_time:"<<*result<<std::endl;
            return std::distance(std::begin(processing_time), result);
        }

    };
    void run_udp_manager(int) {
        repeat([this]{
            return _udp_forward.on_new_initial_context().then([this]() mutable {
                auto ic = _udp_forward.get_initial_context();

                do_with(flow_operator(ic.get_sd_async_flow(),(*this)), [this](flow_operator& r){
                    r.events_registration();
                    return r.run_ips();
                });

                return stop_iteration::no;
            });
        });
    }

    struct info {
        uint64_t ingress_received;
        uint64_t egress_send;
        size_t active_flow_num;

        unsigned mica_timeout_error;
        unsigned insufficient_mica_rd_erorr;

        uint64_t mica_send;
        uint64_t mica_recv;

        unsigned epoch_mismatch;

        void operator+=(const info& o) {
            ingress_received += o.ingress_received;
            egress_send += o.egress_send;
            active_flow_num += o.active_flow_num;
            mica_timeout_error += o.mica_timeout_error;
            insufficient_mica_rd_erorr += o.insufficient_mica_rd_erorr;
            mica_send += o.mica_send;
            mica_recv += o.mica_recv;
            epoch_mismatch += o.epoch_mismatch;
        }
    };
    info _old{0,0,0,0,0,0,0, 0};
    unsigned _mica_timeout_error = 0;
    unsigned _insufficient_mica_rd_erorr=0;

    future<info> get_info() {
        /*return make_ready_future<info>(info{_ingress_port.get_qp_wrapper().rx_pkts(),
                                            _egress_port.get_qp_wrapper().tx_pkts(),
                                            _egress_port.peek_failed_send_cout(),
                                            _udp_manager.peek_active_flow_num()});*/
        return make_ready_future<info>(info{port_manager::get().pOrt(0).rx_pkts(),
                                            port_manager::get().pOrt(0).tx_pkts(),
                                            _udp_forward.peek_active_flow_num(),
                                            _mica_timeout_error,
                                            _insufficient_mica_rd_erorr,
                                            port_manager::get().pOrt(1).rx_pkts(),
                                            port_manager::get().pOrt(1).tx_pkts(),
                                            });
    }
    void collect_stats(int) {
        repeat([this]{
            return forwarders.map_reduce(adder<info>(), &forwarder::get_info).then([this](info i){
                fprint(std::cout, "ingress_received=%d, egress_send=%d, active_flow_num=%d, mica_timeout_error=%d, insufficient_mica_rd_erorr=%d, mica_send=%d, mica_recv=%d.\n",
                        i.ingress_received-_old.ingress_received,
                        i.egress_send - _old.egress_send,
                        i.active_flow_num,
                        i.mica_timeout_error - _old.mica_timeout_error,
                        i.insufficient_mica_rd_erorr - _old.insufficient_mica_rd_erorr,
                        i.mica_send - _old.mica_send,
                        i.mica_recv - _old.mica_recv);
                _old = i;
            }).then([]{
                return seastar::sleep(1s).then([]{
                    return stop_iteration::no;
                });
            });
        });
    }
public:
    IPS ips;
    batch _batch;
    uint64_t _pkt_counter;
};

static void
my_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
        void *obj, unsigned i)
{
    gpu_mem_map(obj,mp->elt_size);
    //struct rte_mbuf* rte_pkt=(struct rte_mbuf*)obj;
    //unsigned char *t =rte_pktmbuf_mtod(rte_pkt, unsigned char*);
    //char* raw_packet = (char*)t;
    printf("obj_addr:%p\n",obj);
   // printf("raw_packet_addr:%p\n",raw_packet);

}

int main(int ac, char** av) {
    app_template app;
    sd_async_flow_manager<tcp_ppr> m1;
    sd_async_flow_manager<udp_ppr> m2;
    async_flow_manager<tcp_ppr> m3;
    async_flow_manager<udp_ppr> m4;

    return app.run_deprecated(ac, av, [&app] {
        auto& opts = app.configuration();

        port_manager::get().add_port(opts, 0, port_type::standard).then([&opts]{
            return port_manager::get().add_port(opts, 1, port_type::fdir);
        }).then([&opts]{
            return mica_manager::get().add_mica_client(opts, 1);
        }).then([]{
            return hook_manager::get().add_hook_point(hook_type::sd_async_flow, 0);
        }).then([]{
            engine().at_exit([]{
                return forwarders.stop();
            });
            return forwarders.start();
        }).then([]{
            return hook_manager::get().invoke_on_all(0, &hook::check_and_start);
        }).then([]{
                //std::cout<<"size: "<<netstar_pools.size()<<std::endl;
                //for(unsigned int i = 0; i<netstar_pools.size();i++){
                //    std::cout<<"mem_map: "<<i<<std::endl;
                //    gpu_mem_map(netstar_pools[i],mbufs_per_queue_tx*inline_mbuf_size+mbuf_cache_size+sizeof(struct rte_pktmbuf_pool_private));
                //}

                uint32_t times=0;
                times=rte_mempool_obj_iter(netstar_pools[1],my_obj_init,NULL);
                times=rte_mempool_obj_iter(netstar_pools[0],my_obj_init,NULL);
                printf("times:%d\n",times);
                return make_ready_future<>();

        }).then([]{
            return forwarders.invoke_on_all(&forwarder::run_udp_manager, 1);
        }).then([]{
            return forwarders.invoke_on(0, &forwarder::collect_stats, 1);
        }).then([]{
            fprint(std::cout, "forwarder runs!\n");

        });

    });
}
