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


#include "core/reactor.hh"
#include "core/app-template.hh"
#include "core/print.hh"
#include "core/distributed.hh"
#include "core/print.hh"
#include "core/sleep.hh"

#include "net/udp.hh"
#include "net/ip_checksum.hh"
#include "net/ip.hh"
#include "net/net.hh"
#include "net/packet.hh"
#include "net/byteorder.hh"

#include "netstar/work_unit.hh"
#include "netstar/port_env.hh"
#include "netstar/af/sd_async_flow.hh"
#include "netstar/mica_client.hh"
#include "netstar/extendable_buffer.hh"

#include "bess/bess_flow_gen.hh"

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
#define GPU_BATCH_SIZE 20000

#define COMPUTE_RATIO 50

using namespace seastar;
using namespace netstar;
using namespace std;
using namespace std::chrono_literals;
using std::vector;

enum class dummy_udp_events : uint8_t{
    pkt_in=0
};

class dummy_udp_ppr{
private:
    bool _is_client;
    timer<lowres_clock> _t;
    std::function<void(bool)> _close_fn;
public:
    using EventEnumType = dummy_udp_events;
    using FlowKeyType = net::l4connid<net::ipv4_traits>;
    using HashFunc = net::l4connid<net::ipv4_traits>::connid_hash;

    dummy_udp_ppr(bool is_client, std::function<void(bool)> close_fn)
        : _is_client(is_client)
        , _close_fn(std::move(close_fn)){
        _t.set_callback([this]{
            // fprint(std::cout, "timer called.\n");
            this->_close_fn(this->_is_client);
        });
        _t.arm(100s);
    }

public:
    generated_events<EventEnumType> handle_packet_send(net::packet& pkt){
        generated_events<EventEnumType> ge;
        ge.event_happen(dummy_udp_events::pkt_in);
        if(_t.armed()) {
            _t.cancel();
            _t.arm(100s);
        }
        return ge;
    }

    generated_events<EventEnumType> handle_packet_recv(net::packet& pkt){
        generated_events<EventEnumType> ge;
        ge.event_happen(dummy_udp_events::pkt_in);
        return ge;
    }

    FlowKeyType get_reverse_flow_key(net::packet& pkt){
        auto ip_hd_ptr = pkt.get_header<net::ip_hdr>(sizeof(net::eth_hdr));
        auto udp_hd_ptr = pkt.get_header<net::udp_hdr>(sizeof(net::eth_hdr)+sizeof(net::ip_hdr));
        return FlowKeyType{net::ntoh(ip_hd_ptr->src_ip),
                           net::ntoh(ip_hd_ptr->dst_ip),
                           net::ntoh(udp_hd_ptr->src_port),
                           net::ntoh(udp_hd_ptr->dst_port)};
    }

public:
    struct async_flow_config {
        static constexpr int max_event_context_queue_size = 6;
        static constexpr int new_flow_queue_size = 1000;
        static constexpr int max_flow_table_size = 100000;
        static constexpr int max_directions = 2;

        static FlowKeyType get_flow_key(net::packet& pkt){
            auto ip_hd_ptr = pkt.get_header<net::ip_hdr>(sizeof(net::eth_hdr));
            auto udp_hd_ptr = pkt.get_header<net::udp_hdr>(sizeof(net::eth_hdr)+sizeof(net::ip_hdr));
            return FlowKeyType{net::ntoh(ip_hd_ptr->dst_ip),
                               net::ntoh(ip_hd_ptr->src_ip),
                               net::ntoh(udp_hd_ptr->dst_port),
                               net::ntoh(udp_hd_ptr->src_port)};
        }
    };
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

        // Map ips object

        gpu_mem_map(this, sizeof(IPS));
    }
    ~IPS(){
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
public:
    port& _ingress_port;
    std::experimental::optional<subscription<net::packet>> _ingress_port_sub;

    port& _egress_port;
    std::experimental::optional<subscription<net::packet>> _egress_port_sub;


    sd_async_flow_manager<dummy_udp_ppr> _udp_manager;
    sd_async_flow_manager<dummy_udp_ppr>::external_io_direction _udp_manager_ingress;
    sd_async_flow_manager<dummy_udp_ppr>::external_io_direction _udp_manager_egress;

    mica_client& _mc;
    uint64_t _pkt_counter;



    forwarder (ports_env& all_ports, per_core_objs<mica_client>& mica_clients)
        : _ingress_port(std::ref(all_ports.local_port(0)))
        , _egress_port(std::ref(all_ports.local_port(1)))
        , _udp_manager_ingress(0)
        , _udp_manager_egress(1)
        , _mc(std::ref(mica_clients.local_obj()))
        ,_pkt_counter(0){
    }

    future<> stop(){
        return make_ready_future<>();
    }

    future<> mica_test(int ) {
        // only test mica performance on thread 1.
        return repeat([this]{
            uint64_t key = engine().cpu_id()+1;
            extendable_buffer key_buf;
            key_buf.fill_data(key);

            return _mc.query(Operation::kGet,sizeof(key), key_buf.get_temp_buffer(),
                             0, temporary_buffer<char>()).then([this](mica_response response){
                assert(response.get_result() == Result::kNotFound);

                uint64_t key = engine().cpu_id()+1;
                extendable_buffer key_buf;
                key_buf.fill_data(key);

                uint64_t val = 6;
                extendable_buffer val_buf;
                val_buf.fill_data(val);
                return _mc.query(Operation::kSet, sizeof(key), key_buf.get_temp_buffer(),
                                 sizeof(val), val_buf.get_temp_buffer());
            }).then([this](mica_response response){
                assert(response.get_result() == Result::kSuccess);

                uint64_t key = engine().cpu_id()+1;
                extendable_buffer key_buf;
                key_buf.fill_data(key);

                return _mc.query(Operation::kGet,sizeof(key), key_buf.get_temp_buffer(),
                                 0, temporary_buffer<char>());
            }).then([this](mica_response response){
                assert(response.get_value<uint64_t>() == 6);

                uint64_t key = engine().cpu_id()+1;
                extendable_buffer key_buf;
                key_buf.fill_data(key);

                return _mc.query(Operation::kDelete,
                                 sizeof(key), key_buf.get_temp_buffer(),
                                 0, temporary_buffer<char>());
            }).then([this](mica_response response){
                assert(response.get_result() == Result::kSuccess);
            }).then_wrapped([](auto&& f){
                try{
                    f.get();
                    fprint(std::cout, "mica_test succeeds on core %d!\n", engine().cpu_id());
                    return make_ready_future<stop_iteration>(stop_iteration::yes);
                }
                catch(...) {
                    fprint(std::cout, "mica_test fails on core %d, retry in 3s.\n", engine().cpu_id());
                    return sleep(3s).then([]{
                        return stop_iteration::no;
                    });
                }
            });
        });
    }

    void configure(int i) {

        auto udp_manager_ingress_output_fn = [this](net::packet pkt) {
            // fprint(std::cout, "udp_manager_ingress_output_fn receives.\n");
            auto eth_h = pkt.get_header<net::eth_hdr>(0);
            eth_h->src_mac = net::ethernet_address{0x3c, 0xfd, 0xfe, 0x06, 0x09, 0x62};
            eth_h->dst_mac = net::ethernet_address{0x3c, 0xfd, 0xfe, 0x06, 0x07, 0x82};
            _ingress_port.send(std::move(pkt));
            return make_ready_future<>();
        };

        auto udp_manager_egress_output_fn = [this](net::packet pkt) {
            // fprint(std::cout, "udp_manager_egress_output_fn receives.\n");
            auto eth_h = pkt.get_header<net::eth_hdr>(0);
            eth_h->src_mac = net::ethernet_address{0x3c, 0xfd, 0xfe, 0x06, 0x09, 0x60};
            eth_h->dst_mac = net::ethernet_address{0x3c, 0xfd, 0xfe, 0x06, 0x08, 0x00};
            _ingress_port.send(std::move(pkt));
            return make_ready_future<>();
        };

        _udp_manager_ingress.register_to_manager(_udp_manager,
                                                 std::move(udp_manager_egress_output_fn),
                                                 _udp_manager_egress);

        _udp_manager_egress.register_to_manager(_udp_manager,
                                                std::move(udp_manager_ingress_output_fn),
                                                _udp_manager_ingress);

        _ingress_port_sub.emplace(_ingress_port.receive([this](net::packet pkt){

            auto eth_h = pkt.get_header<net::eth_hdr>(0);
            if(!eth_h) {
                return make_ready_future<>();
            }

            if(net::ntoh(eth_h->eth_proto) == static_cast<uint16_t>(net::eth_protocol_num::ipv4)) {
                auto ip_h = pkt.get_header<net::ip_hdr>(sizeof(net::eth_hdr));
                if(!ip_h) {
                    return make_ready_future<>();
                }

                if(ip_h->ip_proto == static_cast<uint8_t>(net::ip_protocol_num::udp)) {
                    auto udp_h = pkt.get_header<net::udp_hdr>(sizeof(net::eth_hdr)+sizeof(net::ip_hdr));
                    if(!udp_h) {
                        return make_ready_future<>();
                    }

                    dummy_udp_ppr::FlowKeyType fk{net::ntoh(ip_h->dst_ip),
                                                  net::ntoh(ip_h->src_ip),
                                                  net::ntoh(udp_h->dst_port),
                                                  net::ntoh(udp_h->src_port)};
                    _udp_manager_ingress.get_send_stream().produce(std::move(pkt), &fk);
                    return make_ready_future<>();

                }
                else{
                    return make_ready_future<>();
                }
            }
            else{
                return make_ready_future<>();
            }
        }));
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
    	sd_async_flow<dummy_udp_ppr> _ac;
        forwarder& _f;
        ips_flow_state _fs;
        std::vector<net::packet> packets;
        bool _initialized;


        flow_operator(sd_async_flow<dummy_udp_ppr> ac, forwarder& f)
            : _ac(std::move(ac))
            , _f(f)
            ,_initialized(false){}
        //flow_operator(const flow_operator& other) = delete;
        /*flow_operator(flow_operator&& other) noexcept
            : _ac(std::move(other._ac)),_f(other._f),_fs(other._fs) ,_initialized(other._initialized){

        	for(unsigned int i=0;i<other.packets.size();i++){
        		packets.push_back(std::move(other.packets[i]));
        	}
        }
        ~flow_operator(){
        	std::cout<<"packets.size:"<<packets.size()<<std::endl;
        	std::cout<<"deconstruction:"<<std::endl;

        	assert(packets.size()<100);


        }*/


        void events_registration() {
            _ac.register_events(dummy_udp_events::pkt_in);
        }

        void post_process(){

            _f._pkt_counter-=packets.size();
            assert(_f._pkt_counter>=0);
            process_pkts();
            std::vector<flow_operator*>::iterator it;
            for(it=_f._batch._flows.begin();it!=_f._batch._flows.end();it++){
                if(*it==this){
                    break;
                }
            }
            _f._batch._flows.erase(it);

        }
        void process_pkt(net::packet* pkt, ips_flow_state* fs){


            ips_flow_state old;
            old._alert=fs->_alert;
            old._dfa_id=fs->_dfa_id;
            old._state=fs->_state;
            old.tag=fs->tag;
            std::cout<<"before ips_detect"<<std::endl;
            ips_detect(pkt,fs);
            std::cout<<"after ips_detect"<<std::endl;
            auto state_changed=state_updated(&old,fs);
            if(state_changed) {
                auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                _f._mc.query(Operation::kSet, mica_key(key),
                        mica_value(*fs)).then([this](mica_response response){
                    return make_ready_future<>();
                });
            }

        }

        void forward_pkts(){
            for(unsigned int i=0;i<packets.size();i++){

                std::cout<<"begin to send pkt"<<std::endl;
                _ac.internal_send(std::move(packets[i]));
                std::cout<<"finish sending pkt"<<std::endl;
            }
            packets.clear();
            assert(packets.size()==0);
        }
        void process_pkts(){
            std::cout<<"packets.size:"<<packets.size()<<std::endl;
            for(unsigned int i=0;i<packets.size();i++){
            	std::cout<<"packets.size:"<<packets.size()<<std::endl;
                std::cout<<"process "<<i<<" packets"<<std::endl;
                //process_pkt(&packets[i],&_fs);

            }
            forward_pkts();

        }
        future<>update_state(){
            if(packets.size()==1){   //if it is the first packets of this flow in this batch
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

        }

        future<> run_ips() {
            return _ac.run_async_loop([this](){
                if(_ac.cur_event().on_close_event()) {
                    post_process();
                    return make_ready_future<af_action>(af_action::close_forward);
                }



                if(packets.empty()){
                    _f._batch._flows.push_back(this);
                }
                packets.push_back(std::move(_ac.cur_packet()));
                _f._pkt_counter++;
                std::cout<<"pkt_num:"<<_f._pkt_counter<<std::endl;
                if(_f._pkt_counter>=GPU_BATCH_SIZE&&_f._batch.need_process==false){
                    _f._batch.need_process=true;
                    _f._pkt_counter=0;
                }
                return update_state()                       //update the flow state when receive the first pkt of this flow in this batch.
                        .then([this](){
                    if(_f._batch.need_process==true&&_f._batch.processing==false){
                        //reach batch size schedule
                        _f._batch.processing=true;
                        std::cout<<"schedule_task"<<std::endl;
                        return  _f._batch.schedule_task()
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
             std::cout<<"init_automataState_dfa_id:"<<state._dfa_id<<std::endl;
         }
       void parse_pkt(net::packet *rte_pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){

           aho_pkt->content=(uint8_t*)malloc(rte_pkt->len());
           std::cout<<"    rte_pkt->len():"<<rte_pkt->len()<<std::endl;
           memcpy(aho_pkt->content,reinterpret_cast<uint8_t*>(rte_pkt->get_header(0,sizeof(char))),rte_pkt->len()-1);
           aho_pkt->dfa_id=state->_dfa_id;
           aho_pkt->len=rte_pkt->len();
           std::cout<<"    aho_pkt->len:"<<rte_pkt->len()<<std::endl;
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
               std::cout<<"      dfa_id:"<<dfa_id<<std::endl;
               int len = pkts[I].len;
               std::cout<<"      len:"<<len<<std::endl;
               struct aho_state *st_arr = dfa_arr[dfa_id].root;

               int state = ips_state->_state;
             if(state>=dfa_arr[dfa_id].num_used_states){
                 ips_state->_alert=false;
                 ips_state->_state=state;
                 return;
             }
               std::cout<<"      state:"<<state<<std::endl;
               std::cout<<"      before for loop"<<std::endl;
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
               std::cout<<"      after for loop"<<std::endl;
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


           //int tot_proc = 0;     /* How many packets did we actually match ? */
           //int tot_success = 0;  /* Packets that matched a DFA state */
           // tot_bytes = 0;       /* Total bytes matched through DFAs */

           for(i = 0; i < num_pkts; i += BATCH_SIZE) {
               std::cout<<"    before process_batch"<<std::endl;
               process_batch(dfa_arr, &pkts[i], mp_list,state);
               std::cout<<"    after process_batch"<<std::endl;

               for(j = 0; j < BATCH_SIZE; j++) {
                   int num_match = mp_list[j].num_match;
                   assert(num_match < MAX_MATCH);


                   mp_list[j].num_match = 0;
               }
           }



       }
       void ips_detect(net::packet *rte_pkt, struct ips_flow_state* state){

           //cudaError_t err=cudaSuccess;
           struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));
           //err=cudaHostRegister(rte_pkt,sizeof(net::packet),cudaHostRegisterPortable);
           //if(err==cudaSuccess){
           //    printf("cudaHostRegister success!\n");
           //}else if(err==cudaErrorHostMemoryAlreadyRegistered){
              // printf("cudaErrorHostMemoryAlreadyRegistered!\n");
           //}else{
            //   printf("cudaHostRegister fail!\n");
           //}
           std::cout<<"  before parse_pkt"<<std::endl;
           parse_pkt(rte_pkt, state,pkts);
           std::cout<<"  after parse_pkt"<<std::endl;
           struct aho_ctrl_blk worker_cb;
           worker_cb.stats = _f.ips.stats;
           worker_cb.tot_threads = 1;
           worker_cb.tid = 0;
           worker_cb.dfa_arr = _f.ips.dfa_arr;
           worker_cb.pkts = pkts;
           worker_cb.num_pkts = 1;
           std::cout<<"  before ids_func"<<std::endl;
           ids_func(&worker_cb,state);
           std::cout<<"  after ids_func"<<std::endl;
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
        return lhs->packets.size() < rhs->packets.size();
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
        std::vector<flow_operator*> _flows;
        char** gpu_pkts;
        char** gpu_states;
        bool need_process;
        bool processing;

        batch():gpu_pkts(nullptr),gpu_states(nullptr),need_process(false),processing(false){

        }
        ~batch(){

        }



        future<> schedule_task(){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU
            std::cout<<"flow_size:"<<_flows.size()<<std::endl;
            std::cout<<"before sort packet num begin"<<std::endl;
            for(unsigned int i=0;i<_flows.size();i=i+1){
                std::cout<<_flows[i]->packets.size()<<" ";
            }
            std::cout<<"end before sort"<<std::endl;
            sort(_flows.begin(),_flows.end(),CompLess);
            int partition=get_partition();
            assert(partition!=-1);
            std::cout<<"   partition:"<<partition<<std::endl;
            int max_pkt_num_per_flow=_flows[partition]->packets.size();

            int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(char*);
            int ngpu_states = partition * sizeof(char*);
            gpu_pkts = (char **)malloc(ngpu_pkts);
            gpu_states = (char **)malloc(ngpu_states);
            
            assert(gpu_pkts);
            assert(gpu_states);

            // Clear and map gpu_pkts and gpu_states
            memset(gpu_pkts, 0, ngpu_pkts);
            memset(gpu_states, 0, ngpu_states);
            gpu_mem_map(gpu_pkts, ngpu_pkts);
            gpu_mem_map(gpu_states, ngpu_states);

            //std::cout<<"memory alloc finished"<<std::endl;
            for(int i = 0; i < partition; i++){
                gpu_states[i] = reinterpret_cast<char*>(&(_flows[i]->_fs));
                gpu_mem_map(gpu_states[i], sizeof(struct ips_flow_state));
                //std::cout<<"assign gpu_states["<<i<<"]"<<std::endl;
                for(int j = 0; j < (int)_flows[i]->packets.size(); j++){

                    gpu_pkts[i*max_pkt_num_per_flow+j]=reinterpret_cast<char*>(_flows[i]->packets[j].get_header<net::eth_hdr>(0));
                    //std::cout<<"assign gpu_pkts["<<i<<"]"<<"["<<j<<"]"<<std::endl;
                    
                    // Map every packet
                    gpu_mem_map(gpu_pkts[i*max_pkt_num_per_flow+j], _flows[i]->packets[j].len());
                }
            }



            /////////////////////////////////////////////
            // Launch kernel
           // gpu_launch((char **)gpu_pkts, (char **)gpu_states, (char *)&(_flows[0]->_f.ips), max_pkt_num_per_flow, partition);
            //
            /////////////////////////////////////////////
            
            std::cout<<"begin to process_pkts"<<std::endl;

            for(unsigned int i = partition; i < _flows.size(); i++){
                _flows[i]->process_pkts();
            }

            // Wait for GPU process
            //gpu_sync();


            // Unmap every packet
            for(int i = 0; i < partition; i++){
                gpu_mem_unmap(gpu_states[i]);

                for(int j = 0; j < (int)_flows[i]->packets.size(); j++){
                    gpu_mem_unmap(gpu_pkts[i * max_pkt_num_per_flow + j]);
                }
            }
            // Unmap gpu_pkts and gpu_states
            gpu_mem_unmap(gpu_pkts);
            gpu_mem_unmap(gpu_states);

            // Forward GPU packets
            for(int i = 0; i < partition; i++){
                _flows[i]->forward_pkts();
            }


            _flows.clear();
            if(gpu_pkts){
                free(gpu_pkts);
            }
            if(gpu_states){
                free(gpu_states);
            }
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
        uint64_t get_partition(){

            std::vector<float> processing_time;
            for(unsigned int i=0;i<_flows.size();i++){
                float cpu_time=0;
                float gpu_time=_flows[i]->packets.size();
                for(unsigned int j=i+1;j<_flows.size();j++){
                    cpu_time+=_flows[j]->packets.size();
                }
                processing_time.push_back(std::max(gpu_time,cpu_time/COMPUTE_RATIO));
            }


            std::cout<<"packet num begin"<<std::endl;
            for(unsigned int i=0;i<_flows.size();i++){
                std::cout<<_flows[i]->packets.size()<<" ";
            }
            std::cout<<"packet num end"<<std::endl;



            std::cout<<"processing time begin"<<std::endl;
            for(unsigned int i=0;i<processing_time.size();i++){
                std::cout<<processing_time[i]<<" ";
            }
            std::cout<<"processing time end"<<std::endl;


            std::vector<float>::iterator result = std::min_element(std::begin(processing_time), std::end(processing_time));
            std::cout<<"    min_processing_time:"<<*result<<std::endl;
            return std::distance(std::begin(processing_time), result);
        }

    };

    void run_udp_manager(int) {
        repeat([this]{
            return _udp_manager.on_new_initial_context().then([this]() mutable {
                auto ic = _udp_manager.get_initial_context();

                do_with(flow_operator(ic.get_sd_async_flow(), (*this)), [](flow_operator& r){
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
        unsigned egress_failed_send;
        size_t active_flow_num;

        unsigned mica_timeout_error;
        unsigned insufficient_mica_rd_erorr;

        void operator+=(const info& o) {
            ingress_received += o.ingress_received;
            egress_send += o.egress_send;
            egress_failed_send += o.egress_failed_send;
            active_flow_num += o.active_flow_num;
            mica_timeout_error += o.mica_timeout_error;
            insufficient_mica_rd_erorr += o.insufficient_mica_rd_erorr;
        }
    };
    info _old{0,0,0,0,0,0};
    unsigned _mica_timeout_error = 0;
    unsigned _insufficient_mica_rd_erorr=0;

    future<info> get_info() {
        /*return make_ready_future<info>(info{_ingress_port.get_qp_wrapper().rx_pkts(),
                                            _egress_port.get_qp_wrapper().tx_pkts(),
                                            _egress_port.peek_failed_send_cout(),
                                            _udp_manager.peek_active_flow_num()});*/
        return make_ready_future<info>(info{_ingress_port.get_qp_wrapper().rx_pkts(),
                                            _ingress_port.get_qp_wrapper().tx_pkts(),
                                            _ingress_port.peek_failed_send_cout(),
                                            _udp_manager.peek_active_flow_num(),
                                            _mica_timeout_error,
                                            _insufficient_mica_rd_erorr});
    }
    void collect_stats(int){
        repeat([this]{
            return forwarders.map_reduce(adder<info>(), &forwarder::get_info).then([this](info i){
                fprint(std::cout, "ingress_received=%d, egress_send=%d, egress_failed_send=%d, active_flow_num=%d, mica_timeout_error=%d, insufficient_mica_rd_erorr=%d.\n",
                        i.ingress_received-_old.ingress_received,
                        i.egress_send - _old.egress_send,
                        i.egress_failed_send - _old.egress_failed_send,
                        i.active_flow_num,
                        i.mica_timeout_error - _old.mica_timeout_error,
                        i.insufficient_mica_rd_erorr - _old.insufficient_mica_rd_erorr);
                _old = i;
            }).then([]{
                return seastar::sleep(1s).then([]{
                    return stop_iteration::no;
                });
            });
        });
    };
public:
    IPS ips;
    batch _batch;
};





int main(int ac, char** av) {
    app_template app;
    ports_env all_ports;
    per_core_objs<mica_client> mica_clients;
    vector<vector<port_pair>> queue_map;

    return app.run_deprecated(ac, av, [&app, &all_ports, &mica_clients, &queue_map] {
        auto& opts = app.configuration();
        return all_ports.add_port(opts, 0, smp::count, port_type::netstar_dpdk).then([&opts, &all_ports]{
            return all_ports.add_port(opts, 1, smp::count, port_type::fdir);
        }).then([&mica_clients]{
           return mica_clients.start(&mica_clients);
        }).then([&all_ports, &mica_clients]{
            return mica_clients.invoke_on_all([&all_ports](mica_client& mc){
                mc.configure_ports(all_ports, 1, 1);
            });
        }).then([&opts, &all_ports, &queue_map]{
            queue_map = calculate_queue_mapping(opts, all_ports.local_port(1));
        }).then([&mica_clients, &opts, &queue_map]{
            return mica_clients.invoke_on_all([&opts, &queue_map](mica_client& mc){
                mc.bootup(opts, queue_map);
            });
        }).then([&mica_clients]{
            return mica_clients.invoke_on_all([](mica_client& mc){
                mc.start_receiving();
            });
        }).then([&all_ports, &mica_clients]{
            return forwarders.start(std::ref(all_ports), std::ref(mica_clients));
        })/*.then([]{
            return forwarders.invoke_on_all(&forwarder::mica_test, 1);
        }).then([]{
            return forwarders.invoke_on_all(&forwarder::mica_test, 1);
        }).then([]{
            return forwarders.invoke_on_all(&forwarder::mica_test, 1);
        })*/.then([]{
            return forwarders.invoke_on_all(&forwarder::configure, 1);
        }).then([]{
            return forwarders.invoke_on_all(&forwarder::run_udp_manager, 1);
        }).then([]{
            return forwarders.invoke_on(0, &forwarder::collect_stats, 1);
        }).then([]{
            fprint(std::cout, "forwarder runs!\n");
            engine().at_exit([]{
                return forwarders.stop();
            });
        });
    });
}

// 1 thread forwarder, sender use static udp traffic gen, 700000 total pps, 1000 flows
// The system barely crashes, which is good.

// When turn on mica debug mode, mica will fail to made an assertion about memory alignment in the packet
// This is easy to reproduce even when 1 flow with 1pps. Please check this out carefully!

// 1r: 8.5M.
// 1r1w: 5.35M
// 2r2w: 3.4M
// 3r3w: 2.43M
