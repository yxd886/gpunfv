#pragma once
#ifndef FIREWALL_H_
#define FIREWALL_H_


#include "nf/nf_common.hh"

#include "netstar/af/async_flow_util.hh"

#include <vector>
#include <iostream>

using namespace seastar;



class Firewall{
public:
    Firewall() {

        if(DEBUG==1) printf("Initializing a firewall\n");
        /*auto rules_config = ::mica::util::Config::load_file("firewall.json").get("rules");
        for (size_t i = 0; i < rules_config.size(); i++) {
            auto rule_conf = rules_config.get(i);
            uint16_t src_port = (uint16_t)(
                    rule_conf.get("src_port").get_uint64());
            uint16_t dst_port = (uint16_t)(
                rule_conf.get("dst_port").get_uint64());

            uint32_t src_addr = ::mica::network::NetworkAddress::parse_ipv4_addr(
                rule_conf.get("src_addr").get_str().c_str());
            uint32_t dst_addr = ::mica::network::NetworkAddress::parse_ipv4_addr(
                rule_conf.get("dst_addr").get_str().c_str());
            struct rule r(src_addr,dst_addr,src_port,dst_port);
            rules.push_back(r);


        }*/

    }

    void update_state(struct firewall_state* return_state,struct firewall_state* firewall_state_ptr,net::udp_hdr *tcp){



        return_state->_pass=firewall_state_ptr->_pass;
        // return_state->_recv_ack=tcp->ack.raw;
        // return_state->_sent_seq=tcp->seq.raw;
        // return_state->_tcp_flags=tcp->f_fin;

    }

    void check_session(net::packet* pkt,firewall_state* state){
        net::ip_hdr *iphdr;
        net::udp_hdr *tcp;
        std::vector<rule>::iterator it;
        iphdr =pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));
        tcp = (net::udp_hdr *)((unsigned char *)iphdr +sizeof(net::ip_hdr));
        for(it=rules.begin();it!=rules.end();it++){
            if(iphdr->dst_ip.ip==it->_dst_addr&&tcp->dst_port==it->_dst_port&&iphdr->src_ip.ip==it->_src_addr&&tcp->src_port==it->_src_port){
                state->_pass=false;
                return;
            }
        }
        state->_pass=true;

    }

    bool state_changed(struct firewall_state* src,struct firewall_state* dst){
        if(src->_tcp_flags!=dst->_tcp_flags||src->_recv_ack!=dst->_recv_ack||src->_sent_seq!=dst->_sent_seq){
            return true;
        }
        return false;
    }
    void init_state(firewall_state& fs){
        fs._pass=false;
        fs._recv_ack=0;
        fs._sent_seq=0;
        fs._tcp_flags=0;
    }
    future<netstar::af_action> process_packet(net::packet* rte_pkt, mica_client& mc, firewall_state state, uint64_t key ){


        net::ip_hdr *iphdr;

        iphdr =rte_pkt->get_header<net::ip_hdr>(sizeof(net::eth_hdr));

        if (iphdr->ip_proto!=(uint8_t)net::ip_protocol_num::udp){
            //drop
            if(DEBUG==1) printf("not tcp pkt\n");
            return make_ready_future<netstar::af_action>(netstar::af_action::drop);
        }else{
            //printf("src_addr:%d ,iphdr->dst_addr:%d tcp->src_port:%d tcp->dst_port:%d\n ",iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port);

            //generate key based on five-tuples
            extendable_buffer key_buf;
            key_buf.fill_data(key);
            //generate rte_ring_item
            return mc.query(Operation::kGet,
                    sizeof(key), key_buf.get_temp_buffer(),
                    0, temporary_buffer<char>()).then([&](mica_response response){
                if(response.get_result() == Result::kNotFound){

                    check_session(rte_pkt,&state);
                    //write updated state into mica hash table.
                    extendable_buffer key_buf;
                    key_buf.fill_data(key);
                    extendable_buffer val_buf;
                    val_buf.fill_data(state);

                     return mc.query(Operation::kSet,
                              sizeof(key), key_buf.get_temp_buffer(),
                              sizeof(state), val_buf.get_temp_buffer()).then([&](mica_response response){
                          assert(response.get_key_len() == 0);
                          assert(response.get_val_len() == 0);
                          assert(response.get_result() == Result::kSuccess);

                          if(state._pass==true){
                               //pass
                               return make_ready_future<netstar::af_action>(netstar::af_action::forward);
                           }else{
                               //drop
                               return make_ready_future<netstar::af_action>(netstar::af_action::drop);
                           }
                      });
                }else{

                    memcpy(&state,&(response.get_value<struct firewall_state>()),sizeof(state));
                    if(state._pass==true){
                        //pass
                        return make_ready_future<netstar::af_action>(netstar::af_action::forward);
                    }else{
                        //drop
                        return make_ready_future<netstar::af_action>(netstar::af_action::drop);
                    }
                }

            });


        }

    }

    std::vector<rule> rules;
};


#endif
