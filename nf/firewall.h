#pragma once
#ifndef FIREWALL_H_
#define FIREWALL_H_


#include "nf/nf_common.h"
#include <vector>
#include <iostream>
using namespace seastar;



class Firewall{
public:
    Firewall():_drop(false){

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

    void update_state(struct firewall_state* return_state,struct firewall_state* firewall_state_ptr,net::tcp_hdr *tcp){



        return_state->_pass=firewall_state_ptr->_pass;
        return_state->_recv_ack=tcp->ack.raw;
        return_state->_sent_seq=tcp->seq.raw;
        return_state->_tcp_flags=tcp->f_fin;


	}

	void check_session(struct fivetuple* five,firewall_state* state){

		std::vector<rule>::iterator it;
		for(it=rules.begin();it!=rules.end();it++){
		    if(five->_dst_addr==it->_dst_addr&&five->_dst_port==it->_dst_port&&five->_src_addr==it->_src_addr&&five->_src_port==it->_src_port){
		        state->_pass=false;
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
    future<> process_packet(net::packet* rte_pkt, per_core_objs<mica_client> all_objs){


	    if(DEBUG==1) printf("processing firewall on core:%d\n",rte_lcore_id());
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
	        struct fivetuple tuple(iphdr->src_ip.ip,iphdr->dst_ip.ip,tcp->src_port,tcp->dst_port,iphdr->ip_proto);

	        //printf("src_addr:%d ,iphdr->dst_addr:%d tcp->src_port:%d tcp->dst_port:%d\n ",iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port);


            //generate key based on five-tuples
            struct firewall_state state;
            init_state(state);

	        char* key = reinterpret_cast<char*>(&tuple);
            extendable_buffer key_buf;
            key_buf.fill_data(key);

            extendable_buffer val_buf;
            val_buf.fill_data(state);

            //generate rte_ring_item

            return all_objs.local_obj().query(Operation::kGet,
                    sizeof(key), key_buf.get_temp_buffer(),
                    0, temporary_buffer<char>()).then([&](mica_response response){

                if(response.get_result() == Result::kNotFound){

                    check_session(&tuple,&state);
                }else{

                    memcpy(&state,&(response.get_value<struct firewall_state>()),sizeof(state));
                }
                struct firewall_state f_state;
                struct firewall_state* fw_state=&f_state;
                update_state(fw_state,&state,tcp);
                if(state_changed(&(state),fw_state)){
                    //write updated state into mica hash table.
                    extendable_buffer val_set_buf;
                    val_buf.fill_data(*fw_state);

                    all_objs.local_obj().query(Operation::kSet,
                              sizeof(key), key_buf.get_temp_buffer(),
                              sizeof(state), val_buf.get_temp_buffer()).then([&](mica_response response){
                          assert(response.get_key_len() == 0);
                          assert(response.get_val_len() == 0);
                          assert(response.get_result() == Result::kSuccess);

                      });
                }

                if(state._pass==true){
                    //pass
                    _drop=false;
                    return make_ready_future<>();
                }else{
                    //drop
                    _drop=true;
                    return make_ready_future<>();
                }

            });


	    }


    }

	std::vector<rule> rules;

	bool _drop;


};


#endif
