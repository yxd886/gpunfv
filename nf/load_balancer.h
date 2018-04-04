#pragma once
#ifndef MICA_LOAD_BALANCER_H_
#define MICA_LOAD_BALANCER_H_



#include "mica/util/hash.h"

#include "nf/nf_common.h"
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <time.h>
using namespace seastar;

std::string lists[64]={"192.168.122.131","192.168.122.132","192.168.122.133","192.168.122.134",
                "192.168.122.135","192.168.122.136","192.168.122.137","192.168.122.138",
                "192.168.122.139","192.168.122.140","192.168.122.141","192.168.122.142"};

class Load_balancer{
public:
    Load_balancer(uint32_t cluster_id): _cluster_id(cluster_id),_drop(false){

    }


    void form_list(uint64_t backend_list_bit){
        _backend_list.clear();
        for (uint32_t i=0;i<sizeof(backend_list_bit);i++){
            uint64_t t=backend_list_bit&0x1;
            if(t==1) _backend_list.push_back(::net::ipv4_address(lists[i].c_str()).ip);
            backend_list_bit=backend_list_bit>>1;
        }
    }

    uint32_t next_server(){
        srand((unsigned)time(nullptr));
        long unsigned int index=(long unsigned int)rand()%_backend_list.size();
        return _backend_list[index];
    }

    future<> process_packet(net::packet *rte_pkt,per_core_objs<mica_client> all_objs){

        net::ip_hdr *iphdr;
        net::tcp_hdr *tcp;

        _drop=false;

        iphdr =rte_pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));

        if (iphdr->ip_proto!=(uint8_t)net::ip_protocol_num::tcp){
            //drop
            _drop=true;
            return make_ready_future<>();
        }else{

            tcp = ( net::tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
            uint32_t server=0;

            struct fivetuple tuple(iphdr->src_ip.ip,iphdr->dst_ip.ip,tcp->src_port,tcp->dst_port,iphdr->ip_proto);


            struct load_balancer_state state;
            char* key = reinterpret_cast<char*>(&tuple);
            extendable_buffer key_buf;
            key_buf.fill_data(key);


            return all_objs.local_obj().query(Operation::kGet,
                        sizeof(key), key_buf.get_temp_buffer(),
                        0, temporary_buffer<char>()).then([&](mica_response response){

                    if(response.get_result() == Result::kNotFound){


                        char* cluster_key = reinterpret_cast<char*>(&_cluster_id);
                        uint64_t backend_list=0x1111111;
                        extendable_buffer cluster_key_buf;
                        cluster_key_buf.fill_data(cluster_key);



                        return all_objs.local_obj().query(Operation::kGet,
                                    sizeof(key), cluster_key_buf.get_temp_buffer(),
                                    0, temporary_buffer<char>()).then([&](mica_response response1){

                                if(response.get_result() == Result::kNotFound){

                                    state._backend_list=backend_list;
                                    extendable_buffer cluster_val_buf;
                                    cluster_val_buf.fill_data(state);

                                    all_objs.local_obj().query(Operation::kSet,
                                            sizeof(key), cluster_key_buf.get_temp_buffer(),
                                            sizeof(state), cluster_val_buf.get_temp_buffer()).then([&](mica_response response){
                                        assert(response.get_key_len() == 0);
                                        assert(response.get_val_len() == 0);
                                        assert(response.get_result() == Result::kSuccess);

                                    });

                                }else{

                                    memcpy(&state,&(response1.get_value<struct ips_state>()),sizeof(state));

                                    backend_list=state._backend_list;
                                }
                                form_list(backend_list);

                                server=next_server();
                                state._dst_ip_addr=server;
                                extendable_buffer val_buf;
                                val_buf.fill_data(state);
                                all_objs.local_obj().query(Operation::kSet,
                                             sizeof(key), key_buf.get_temp_buffer(),
                                             sizeof(state), val_buf.get_temp_buffer()).then([&](mica_response response2){
                                         assert(response2.get_key_len() == 0);
                                         assert(response2.get_val_len() == 0);
                                         assert(response2.get_result() == Result::kSuccess);

                                     });
                                iphdr->dst_ip.ip=server;
                                _drop=false;
                                return make_ready_future<>();




                            });


                    }else{

                        memcpy(&state,&(response.get_value<struct ips_state>()),sizeof(state));

                        server=state._dst_ip_addr;

                        //To do: send this packet to address server.
                        iphdr->dst_ip.ip=server;
                        _drop=false;
                        return make_ready_future<>();
                    }



                });

        }
    }



uint32_t _cluster_id;
std::vector<uint32_t> _backend_list;
bool _drop;
};

#endif
