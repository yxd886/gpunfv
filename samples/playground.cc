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


#include <vector>
#include <iostream>
#include "nf/aho-corasick/fpp.h"
#include "nf/aho-corasick/aho.h"
#define MAX_MATCH 8192
#include <stdlib.h>
#include <time.h>
#include <cuda_runtime.h>
#include <helper_cuda.h>

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
        _t.arm(3s);
    }

public:
    generated_events<EventEnumType> handle_packet_send(net::packet& pkt){
        generated_events<EventEnumType> ge;
        ge.event_happen(dummy_udp_events::pkt_in);
        if(_t.armed()) {
            _t.cancel();
            _t.arm(3s);
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
        static constexpr int max_event_context_queue_size = 5;
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
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;

};

class forwarder;
distributed<forwarder> forwarders;

class forwarder {
    port& _ingress_port;
    std::experimental::optional<subscription<net::packet>> _ingress_port_sub;

    port& _egress_port;
    std::experimental::optional<subscription<net::packet>> _egress_port_sub;


    sd_async_flow_manager<dummy_udp_ppr> _udp_manager;
    sd_async_flow_manager<dummy_udp_ppr>::external_io_direction _udp_manager_ingress;
    sd_async_flow_manager<dummy_udp_ppr>::external_io_direction _udp_manager_egress;

    mica_client& _mc;

public:
    forwarder (ports_env& all_ports, per_core_objs<mica_client>& mica_clients)
        : _ingress_port(std::ref(all_ports.local_port(0)))
        , _egress_port(std::ref(all_ports.local_port(1)))
        , _udp_manager_ingress(0)
        , _udp_manager_egress(1)
        , _mc(std::ref(mica_clients.local_obj())){
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

    class ips_runner {
        sd_async_flow<dummy_udp_ppr> _ac;
        forwarder& _f;
        ips_flow_state _fs;
    public:
        ips_runner(sd_async_flow<dummy_udp_ppr> ac, forwarder& f)
            : _ac(std::move(ac))
            , _f(f){}

        void events_registration() {
            _ac.register_events(dummy_udp_events::pkt_in);
        }

        future<> run_ips() {
            return _ac.run_async_loop([this](){
                if(_ac.cur_event().on_close_event()) {
                    return make_ready_future<af_action>(af_action::close_forward);
                }
                auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                return _f._mc.query(Operation::kGet, mica_key(key),
                        mica_value(0, temporary_buffer<char>())).then([this](mica_response response){
                    if(response.get_result() == Result::kNotFound) {
                        init_automataState(_fs);
                        auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                        return _f._mc.query(Operation::kSet, mica_key(key),
                                mica_value(_fs)).then([this](mica_response response){
                            return forward_packet(_fs);
                        });
                    }
                    else {
                        _fs = response.get_value<ips_flow_state>();
                        ips_flow_state old=response.get_value<ips_flow_state>();
                        ips_detect(&(_ac.cur_packet()),&_fs);
                        auto state_changed=state_updated(&old,&_fs);
                        if(state_changed) {
                            auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                            return _f._mc.query(Operation::kSet, mica_key(key),
                                    mica_value(_fs)).then([this](mica_response response){
                                return forward_packet(_fs);
                            });
                        }
                        else{
                            return make_ready_future<af_action>(forward_packet(_fs));
                        }
                    }

                }).then_wrapped([this](auto&& f){
                    try{
                        auto result = f.get0();
                        return result;

                    }
                    catch(...){
                        if(_f._mc.nr_request_descriptors() == 0){
                            _f._insufficient_mica_rd_erorr += 1;
                        }
                        else{
                            _f._mica_timeout_error += 1;
                        }
                        return af_action::drop;
                    }
                });
            });
        }

       void init_automataState(struct ips_flow_state& state){
             srand((unsigned)time(NULL));
             state._state=0;
             state._alert=false;
             state._dfa_id=rand()%AHO_MAX_DFA;
         }
       void parse_pkt(net::packet *rte_pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){

           aho_pkt->content=(uint8_t*)malloc(rte_pkt->len());
           memcpy(aho_pkt->content,reinterpret_cast<uint8_t*>(rte_pkt->get_header(0,sizeof(char))),rte_pkt->len()-1);
           aho_pkt->dfa_id=state->_dfa_id;
           aho_pkt->len=rte_pkt->len();
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
               int len = pkts[I].len;
               struct aho_state *st_arr = dfa_arr[dfa_id].root;

               int state = ips_state->_state;
             if(state>=dfa_arr[dfa_id].num_used_states){
                 ips_state->_alert=false;
                 ips_state->_state=state;
                 return;
             }


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
               process_batch(dfa_arr, &pkts[i], mp_list,state);

               for(j = 0; j < BATCH_SIZE; j++) {
                   int num_match = mp_list[j].num_match;
                   assert(num_match < MAX_MATCH);


                   mp_list[j].num_match = 0;
               }
           }



       }
       void ips_detect(net::packet *rte_pkt, struct ips_flow_state* state){

           cudaError_t err=cudaSuccess;
           struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));
           err=cudaHostRegister(rte_pkt,sizeof(net::packet),cudaHostRegisterPortable);
           if(err==cudaSuccess){
               printf("cudaHostRegister success!\n");
           }else if(err==cudaErrorHostMemoryAlreadyRegistered){
               printf("cudaErrorHostMemoryAlreadyRegistered!\n");
           }else{
               printf("cudaHostRegister fail!\n");
           }
           parse_pkt(rte_pkt, state,pkts);
           struct aho_ctrl_blk worker_cb;
           worker_cb.stats = _f.ips.stats;
           worker_cb.tot_threads = 1;
           worker_cb.tid = 0;
           worker_cb.dfa_arr = _f.ips.dfa_arr;
           worker_cb.pkts = pkts;
           worker_cb.num_pkts = 1;

           ids_func(&worker_cb,state);
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

    void run_udp_manager(int) {
        repeat([this]{
            return _udp_manager.on_new_initial_context().then([this]() mutable {
                auto ic = _udp_manager.get_initial_context();

                do_with(ips_runner(ic.get_sd_async_flow(), (*this)), [](ips_runner& r){
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
    void collect_stats(int) {
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
    }
public:
    IPS ips;
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
