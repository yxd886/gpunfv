#pragma once
#ifndef MICA_NF_STATE_H_
#define MICA_NF_STATE_H_

#define READ 0
#define WRITE 1
#include "net/tcp.hh"
#include "netstar/port.hh"
#include "core/reactor.hh"
#include "core/app-template.hh"
#include "core/print.hh"
#include "core/distributed.hh"

#include "netstar/per_core_objs.hh"
#include "netstar/mica_client.hh"
#include "netstar/extendable_buffer.hh"
#include "netstar/port_env.hh"
#include "core/reactor.hh"
#include "core/app-template.hh"
#include "core/print.hh"
#include "core/distributed.hh"
#include "netstar/netstar_dpdk_device.hh"
#include "net/udp.hh"
#include "net/ip_checksum.hh"
#include "net/ip.hh"
#include "net/virtio.hh"

#include "net/net.hh"
#include "net/packet.hh"
#include "net/byteorder.hh"
#include "core/semaphore.hh"


using namespace seastar;
using namespace netstar;

struct firewall_state{
    uint8_t _tcp_flags;
    uint32_t _sent_seq;
    uint32_t _recv_ack;
    bool _pass;
};

struct server_load{
    uint32_t _ip_addr;
    uint32_t current_load;
    server_load():_ip_addr(0),current_load(0){}
};

struct load_balancer_state{
    uint32_t _dst_ip_addr;
    uint64_t _backend_list;


};

struct nat_state{
    uint32_t _dst_ip_addr;
    uint16_t _dst_port;
    uint64_t _ip_port_list;

};

struct ips_state{
    uint32_t _state;
    uint32_t _dfa_id;
    bool _alert;


 /*   ips_state():_state(0),_dfa_id(0),_alert(false){

    }
    ips_state(uint32_t state):_state(state),_dfa_id(0),_alert(false){

    }
    ips_state(uint32_t state,uint32_t dfa_id):_state(state),_dfa_id(dfa_id),_alert(false){

    }
    ips_state(uint32_t state,uint32_t dfa_id,bool alert):_state(state),_dfa_id(dfa_id),_alert(alert){

    }
    ips_state& operator=(ips_state&& other) {
        _state = std::move(other._state);
        _alert = std::move(other._alert);
        _dfa_id = std::move(other._dfa_id);
        return *this;
    }

    void copy(struct ips_state* c){
        _state=c->_state;
        _alert=c->_alert;
        _dfa_id=c->_dfa_id;


    }
*/

};



#endif
