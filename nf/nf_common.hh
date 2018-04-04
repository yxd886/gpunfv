#pragma once
#ifndef MICA_NF_COMMON_H_
#define MICA_NF_COMMON_H_



#include "mica/util/hash.h"


#include "nf/nf_state.hh"
#include <vector>
#include <iostream>
#define DEBUG 0
/*
struct rte_ring_item{
    uint64_t _key_hash;
    size_t _key_length;
    char* _key;
    struct session_state _state;


    rte_ring_item(uint64_t key_hash,size_t key_length,char* key) :
        _key_hash(key_hash),
        _key_length(key_length),
        _key(key),
        _state()
        {}
    rte_ring_item(uint64_t key_hash,size_t key_length,char* key,struct session_state& dst) :
        _key_hash(key_hash),
        _key_length(key_length),
        _key(key),
        _state(dst)
        {}
};*/

/*
typedef ::mica::alloc::HugeTLBFS_SHM Alloc;

struct DPDKConfig : public ::mica::network::BasicDPDKConfig {
  static constexpr bool kVerbose = true;
};

struct DatagramClientConfig
    : public ::mica::datagram::BasicDatagramClientConfig {
  typedef ::mica::network::DPDK<DPDKConfig> Network;
  // static constexpr bool kSkipRX = true;
  // static constexpr bool kIgnoreServerPartition = true;
  // static constexpr bool kVerbose = true;
};

typedef ::mica::datagram::DatagramClient<DatagramClientConfig> Client;

typedef ::mica::table::Result Result;

template <typename T>
static uint64_t hash(const T* key, size_t key_length) {
  return ::mica::util::hash(key, key_length);
}

class ResponseHandler
    : public ::mica::datagram::ResponseHandlerInterface<Client> {
 public:
    ResponseHandler(std::map<uint64_t,uint64_t> *lcore_map,struct rte_ring** worker2interface,struct rte_ring** interface2worker):_lcore_map(lcore_map),_worker2interface(worker2interface),_interface2worker(interface2worker){

    }
  void handle(Client::RequestDescriptor rd, Result result, const char* value,
              size_t value_length,uint64_t key_hash, const Argument& arg) {

   struct session_state*hash_rcv_state=nullptr;
   char* rcv_value=(char*)value;
   std::map<uint64_t,uint64_t>::iterator iter;
   int flag;
    if(result==::mica::table::Result::kSuccess||result==::mica::table::Result::setSuccess){

        if(result==::mica::table::Result::kSuccess){
            if(DEBUG==1) printf("result==::mica::table::Result::kSuccess\n");
            hash_rcv_state= reinterpret_cast<struct session_state*>(rcv_value);
            if(DEBUG==1) printf("received value's lcore_id: %d\n",hash_rcv_state->lcore_id);
            struct rte_ring_item it(0,0,0,*hash_rcv_state);
            if(DEBUG) printf("ips state: %d\n",it._state._ips_state._state);
            //if(DEBUG) printf("the usable size of _interface2worker[%d] is %d\n",hash_rcv_state->lcore_id,rte_ring_get_capacity(_interface2worker[hash_rcv_state->lcore_id]));
            if(DEBUG==1) printf("try to enqueue to _interface2worker[%d]\n",hash_rcv_state->lcore_id);
            flag=rte_ring_enqueue(_interface2worker[hash_rcv_state->lcore_id],static_cast<void*>(&it));
            if(DEBUG==1) printf("enqueue to _interface2worker[%d] completed\n",hash_rcv_state->lcore_id);
            if(flag!=0){
                printf("ring room is not enough!\n");
                exit(-1);
            }
        }
        if(result==::mica::table::Result::setSuccess){
            if(DEBUG==1) printf("result==::mica::table::Result::setSuccess\n");
            hash_rcv_state= reinterpret_cast<struct session_state*>(rcv_value);
            if(DEBUG==1) printf("received value's lcore_id: %d\n",hash_rcv_state->lcore_id);
            struct rte_ring_item it(0,0,0,*hash_rcv_state);
            if(DEBUG==1) printf("try to enqueue to _interface2worker[%d]\n",(*_lcore_map)[key_hash]);
            rte_ring_enqueue(_interface2worker[(*_lcore_map)[key_hash]],static_cast<void*>(&it));
            if(DEBUG==1) printf("enqueue to _interface2worker[%d] completed\n",(*_lcore_map)[key_hash]);
            iter=_lcore_map->find(key_hash);
            _lcore_map->erase(iter);

        }







    }else if(result==::mica::table::Result::kNotFound){
        if(DEBUG==1) printf("NOT FIND THE KEY FROM SERVER\n");
        if(DEBUG==1) printf("try to enqueue to _interface2worker[%d]\n",(*_lcore_map)[key_hash]);
        rte_ring_enqueue(_interface2worker[(*_lcore_map)[key_hash]],static_cast<void*>(nullptr));
        if(DEBUG==1) printf("enqueue to _interface2worker[%d] completed\n",(*_lcore_map)[key_hash]);


    }else if(result==::mica::table::Result::kPartialValue){
        if(DEBUG==1) printf("result==::mica::table::Result::kPartialValue\n");
    }else if(result==::mica::table::Result::kError){
        if(DEBUG==1) printf("result==::mica::table::Result::kError\n");
    }else if(result==::mica::table::Result::kExists){
        if(DEBUG==1) printf("result==::mica::table::Result::kExists\n");
    }else if(result==::mica::table::Result::kInsufficientSpace){
        if(DEBUG==1) printf("result==::mica::table::Result::kInsufficientSpace\n");
    }


  }
  struct rte_ring** _worker2interface;
  struct rte_ring** _interface2worker;
  std::map<uint64_t,uint64_t> *_lcore_map;


};*/

struct rule{
public:

    uint32_t _src_addr;
    uint32_t _dst_addr;
    uint16_t _src_port;
    uint16_t _dst_port;
    rule(uint32_t src_addr,uint32_t dst_addr,uint16_t src_port,uint16_t dst_port):
        _src_addr(src_addr),_dst_addr(dst_addr),_src_port(src_port),_dst_port(dst_port){

    }

};








/**


void* poll_interface2worker_ring(struct rte_ring* interface2worker_ring){
    int aggressive_poll_attemps = 50;
    int flag = 0;
    void* dequeue_output[1];

    for(int i=0; i<aggressive_poll_attemps; i++){
        flag = rte_ring_sc_dequeue(interface2worker_ring, dequeue_output);

        if(flag != 0){
            continue;
        }
        else{
            return dequeue_output[0];
        }
    }

    for(;;){
        flag = rte_ring_sc_dequeue(interface2worker_ring, dequeue_output);

        if(flag != 0){
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        else{
            return dequeue_output[0];
        }
    }
}

void* get_value(struct rte_ring* interface2worker_ring){

    return poll_interface2worker_ring(interface2worker_ring);
}
*/
struct fivetuple{
public:
    uint32_t _src_addr;
    uint32_t _dst_addr;
    uint16_t _src_port;
    uint16_t _dst_port;
    uint8_t _next_proto_id;
    fivetuple(uint32_t src_addr,uint32_t dst_addr,uint16_t src_port,uint16_t dst_port,uint8_t next_proto_id):
        _src_addr(src_addr),_dst_addr(dst_addr),_src_port(src_port),_dst_port(dst_port),_next_proto_id(next_proto_id){

    }


};




#endif
