#pragma once
#ifndef MICA_NAT_H_
#define MICA_NAT_H_



#include "mica/util/hash.h"

#include "nf/nf_common.h"
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <time.h>
using namespace seastar;

std::string ip_lists[64]={"192.168.122.131","192.168.122.132","192.168.122.133","192.168.122.134",
                "192.168.122.135","192.168.122.136","192.168.122.137","192.168.122.138",
                "192.168.122.139","192.168.122.140","192.168.122.141","192.168.122.142"};
uint16_t port_lists[64]={10012,10013,10014,10015,10016,10017,10018,10019,10020,10021,10022,10023,10024,10025,10026,10027,10028};

class NAT{
public:
    NAT(uint32_t cluster_id):
        _cluster_id(cluster_id),_drop(false){

    }


    void form_list(uint64_t backend_list_bit){
        _ip_list.clear();
        for (uint32_t i=0;i<sizeof(backend_list_bit);i++){
            uint64_t t=backend_list_bit&0x1;
            if(t==1){
                _ip_list.push_back(::net::ipv4_address(ip_lists[i].c_str()).ip);
                _port_list.push_back(port_lists[i]);
            }

            backend_list_bit=backend_list_bit>>1;
        }
    }

    void select_ip_port(uint32_t* ip,uint16_t* port){
        srand((unsigned)time(nullptr));
        long unsigned int index=(long unsigned int)rand()%_ip_list.size();
        *port=_port_list[index];
        *ip=_ip_list[index];
        return;
    }

    void update_packet_header(uint32_t ip, uint16_t port,net::packet* rte_pkt){
        net::ip_hdr *iphdr;
        net::tcp_hdr *tcp;
        iphdr =rte_pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));
        tcp = ( net::tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
        iphdr->dst_ip.ip=ip;
        tcp->dst_port=port;
        return;
    }

    future<> process_packet(net::packet* rte_pkt,per_core_objs<mica_client> all_objs){
        net::ip_hdr *iphdr;
        net::tcp_hdr *tcp;

        _drop=false;
        uint64_t ip_port_list_bit=0x111111;


        iphdr =rte_pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));

        if (iphdr->ip_proto!=(uint8_t)net::ip_protocol_num::tcp){
            //drop
            _drop=true;
            return make_ready_future<>();
        }else{

            tcp = ( net::tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));

            struct fivetuple tuple(iphdr->src_ip.ip,iphdr->dst_ip.ip,tcp->src_port,tcp->dst_port,iphdr->ip_proto);
            struct nat_state state;
            char* key = reinterpret_cast<char*>(&tuple);
            extendable_buffer key_buf;
            key_buf.fill_data(key);
            return all_objs.local_obj().query(Operation::kGet,
                        sizeof(key), key_buf.get_temp_buffer(),
                        0, temporary_buffer<char>()).then([&](mica_response response){

                    if(response.get_result() == Result::kNotFound){

                        char* cluster_key = reinterpret_cast<char*>(&_cluster_id);
                        extendable_buffer  cluster_key_buf;
                        cluster_key_buf.fill_data(cluster_key);
                        all_objs.local_obj().query(Operation::kGet,
                                    sizeof(cluster_key_buf), cluster_key_buf.get_temp_buffer(),
                                    0, temporary_buffer<char>()).then([&](mica_response response1){
                                if(response1.get_result() == Result::kNotFound){


                                    extendable_buffer cluster_val_buf;
                                    state._ip_port_list=ip_port_list_bit;
                                    cluster_val_buf.fill_data(state);


                                    all_objs.local_obj().query(Operation::kSet,
                                            sizeof(key), cluster_key_buf.get_temp_buffer(),
                                            sizeof(state), cluster_val_buf.get_temp_buffer()).then([&](mica_response response){
                                        assert(response.get_key_len() == 0);
                                        assert(response.get_val_len() == 0);
                                        assert(response.get_result() == Result::kSuccess);

                                    });


                                }else{
                                    memcpy(&state,&(response1.get_value<struct nat_state>()),sizeof(state));

                                    ip_port_list_bit=state._ip_port_list;

                                }
                            });
                        form_list(ip_port_list_bit);
                        uint32_t select_ip=0;
                        uint16_t select_port=0;
                        select_ip_port(&select_ip,&select_port);
                        extendable_buffer tuple_val_buf;
                        state._dst_ip_addr=select_ip;
                        state._dst_port=select_port;
                        tuple_val_buf.fill_data(state);

                        all_objs.local_obj().query(Operation::kSet,
                                sizeof(key), tuple_val_buf.get_temp_buffer(),
                                sizeof(state), tuple_val_buf.get_temp_buffer()).then([&](mica_response response){
                            assert(response.get_key_len() == 0);
                            assert(response.get_val_len() == 0);
                            assert(response.get_result() == Result::kSuccess);

                        });
                        extendable_buffer reverse_val_buf;
                        state._dst_ip_addr=iphdr->src_ip.ip;
                        state._dst_port=tcp->src_port;
                        reverse_val_buf.fill_data(state);

                        all_objs.local_obj().query(Operation::kSet,
                                sizeof(key), reverse_val_buf.get_temp_buffer(),
                                sizeof(state), reverse_val_buf.get_temp_buffer()).then([&](mica_response response){
                            assert(response.get_key_len() == 0);
                            assert(response.get_val_len() == 0);
                            assert(response.get_result() == Result::kSuccess);

                        });
                        update_packet_header(select_ip,select_port,rte_pkt);
                        return make_ready_future<>();



                    }else{
                        memcpy(&state,&(response.get_value<struct nat_state>()),sizeof(state));
                        update_packet_header(state._dst_ip_addr,state._dst_port,rte_pkt);
                        return make_ready_future<>();

                    }



                });




        }
    }




uint32_t _cluster_id;
std::vector<uint32_t> _ip_list;
std::vector<uint16_t> _port_list;
bool _drop;
};

#endif
