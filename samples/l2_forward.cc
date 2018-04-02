/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <sys/time.h>
#include <unistd.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>


#include "nf/aho-corasick/fpp.h"
#include "nf/aho-corasick/aho.h"

#include <helper_functions.h>
#include <helper_cuda.h>
#include <cuda_runtime.h>
#include <cuda_profiler_api.h>
#include "playground.hh"
#include <chrono>
#include <thread>
#include <iostream>
#include <vector>

#define APP_LOOKUP_EXACT_MATCH          0
#define APP_LOOKUP_LPM                  1
#define DO_RFC_1812_CHECKS

#ifndef APP_LOOKUP_METHOD
#define APP_LOOKUP_METHOD             APP_LOOKUP_LPM
#endif

/*
 *  When set to zero, simple forwaring path is eanbled.
 *  When set to one, optimized forwarding path is enabled.
 *  Note that LPM optimisation path uses SSE4.1 instructions.
 */
#if ((APP_LOOKUP_METHOD == APP_LOOKUP_LPM) && !defined(__SSE4_1__))
#define ENABLE_MULTI_BUFFER_OPTIMIZE	0
#else
#define ENABLE_MULTI_BUFFER_OPTIMIZE	1
#endif

#if (APP_LOOKUP_METHOD == APP_LOOKUP_EXACT_MATCH)
#include <rte_hash.h>
#elif (APP_LOOKUP_METHOD == APP_LOOKUP_LPM)
#include <rte_lpm.h>
#include <rte_lpm6.h>
#else
#error "APP_LOOKUP_METHOD set to incorrect value"
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
                       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr) \
	addr[0],  addr[1], addr[2],  addr[3], \
	addr[4],  addr[5], addr[6],  addr[7], \
	addr[8],  addr[9], addr[10], addr[11],\
	addr[12], addr[13],addr[14], addr[15]
#endif


#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

#define MAX_JUMBO_PKT_LEN  9600

#define IPV6_ADDR_LEN 16

#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed depending on user input, taking
 *  into account memory for rx and tx hardware rings, cache per lcore and mtable per port per lcore.
 *  RTE_MAX is used to ensure that NB_MBUF never goes below a minimum value of 8192
 */

#define NB_MBUF RTE_MAX	(																	\
				(nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +							\
				nb_ports*nb_lcores*MAX_PKT_BURST +											\
				nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +								\
				nb_lcores*MEMPOOL_CACHE_SIZE),												\
				(unsigned)8192)

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	(MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

/* Used to mark destination port as 'invalid'. */
#define	BAD_PORT	((uint16_t)-1)

#define FWDSTEP	4

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static __m128i val_eth[RTE_MAX_ETHPORTS];

/* replace first 12B of the ethernet header. */
#define	MASK_ETH	0x3f

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;
static int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
static int numa_on = 1; /**< NUMA is enabled by default. */

static uint64_t timer_period = 1;

#if (APP_LOOKUP_METHOD == APP_LOOKUP_EXACT_MATCH)
static int ipv6 = 0; /**< ipv6 is false by default. */
#endif


#define MAX_MATCH 8192

struct port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;
struct port_statistics statistics[RTE_MAX_ETHPORTS][10];


struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024
struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};

static struct lcore_params * lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
				sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf;

static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];
struct  timeval    tv;




#if (APP_LOOKUP_METHOD == APP_LOOKUP_LPM)
struct ipv4_l3fwd_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct ipv6_l3fwd_route {
	uint8_t ip[16];
	uint8_t  depth;
	uint8_t  if_out;
};



#define IPV4_L3FWD_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_route_array) / sizeof(ipv4_l3fwd_route_array[0]))
#define IPV6_L3FWD_NUM_ROUTES \
	(sizeof(ipv6_l3fwd_route_array) / sizeof(ipv6_l3fwd_route_array[0]))

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

typedef struct rte_lpm lookup_struct_t;
typedef struct rte_lpm6 lookup6_struct_t;
static lookup_struct_t *ipv4_l3fwd_lookup_struct[NB_SOCKETS];
static lookup6_struct_t *ipv6_l3fwd_lookup_struct[NB_SOCKETS];
#endif

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	lookup_struct_t * ipv4_lookup_struct;
#if (APP_LOOKUP_METHOD == APP_LOOKUP_LPM)
	lookup6_struct_t * ipv6_lookup_struct;
#else
	lookup_struct_t * ipv6_lookup_struct;
#endif
} __rte_cache_aligned;





static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* Send burst of packets on an output interface */
uint64_t pre_total_rx;
uint64_t pre_total_tx;
uint64_t pre_total_drop;

std::chrono::time_point<std::chrono::steady_clock> started;
std::chrono::time_point<std::chrono::steady_clock> stoped;
using namespace std::chrono;
using steady_clock_type = std::chrono::steady_clock;

#define GPU_BATCH_SIZE 1

#define PRINT_TIME 0

#define COMPUTE_RATIO 100

#define MAX_PKT_SIZE 1500

#define MAX_FLOW_NUM 10000

#define CORE_NUM 4

class rte_packet {


   rte_mbuf* _mbuf;

public:
   // Explicit constructors.
   rte_packet(rte_mbuf* mbuf) {
       assert(mbuf);
       assert(rte_pktmbuf_is_contiguous(mbuf));
       _mbuf = mbuf;
   }

   rte_packet()
       : _mbuf(nullptr) {}

   // Deconstructors
   ~rte_packet() {

   }

   // Copy construct/assign
   rte_packet(const rte_packet& other) = delete;
   rte_packet& operator=(const rte_packet& other) = delete;

   // Move construct/asign
   rte_packet(rte_packet&& other) noexcept
       : _mbuf(other._mbuf) {
       other._mbuf = nullptr;
   }
   rte_packet& operator=(rte_packet&& other) noexcept {
       if(this != &other) {
           this->~rte_packet();
           new (this) rte_packet(std::move(other));
       }
       return *this;
   }

   // Boolean operator overloads
   explicit operator bool() {
       return bool(_mbuf);
   }

   // Get a header pointer.
   template <typename Header>
   Header* get_header(size_t offset = 0) {
       assert(_mbuf);
       if(offset+sizeof(Header) > rte_pktmbuf_pkt_len(_mbuf)) {
           return nullptr;
       }
       return reinterpret_cast<Header*>(rte_pktmbuf_mtod_offset(_mbuf, void*, offset));
   }

   char* get_header(size_t offset, size_t size) {
       if(offset+size > rte_pktmbuf_pkt_len(_mbuf)) {
           return nullptr;
       }

       return reinterpret_cast<char*>(rte_pktmbuf_mtod_offset(_mbuf, void*, offset));
   }

   // Trim some payload from front of the packet
   void trim_front(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_pkt_len(_mbuf));
       rte_pktmbuf_adj(_mbuf, how_much);
   }

   // Trim some payload from the back of the packet
   void trim_back(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_pkt_len(_mbuf));
       rte_pktmbuf_trim(_mbuf, how_much);
   }

   // Append some content to the back of the packet
   void append(size_t how_much) {
       assert(_mbuf);
       assert(how_much <= rte_pktmbuf_tailroom(_mbuf));
       rte_pktmbuf_append(_mbuf, how_much);
   }

   // Prepend a header to the front of the packet.
   template <typename Header>
   Header* prepend_header(size_t extra_size = 0) {
       assert(_mbuf);
       assert(sizeof(Header)+extra_size <= rte_pktmbuf_headroom(_mbuf));
       auto h = rte_pktmbuf_prepend(_mbuf, sizeof(Header) + extra_size);
       return new (h) Header{};
   }

   // Obtain the length of the packet.
   unsigned len() const {
       assert(_mbuf);
       return rte_pktmbuf_pkt_len(_mbuf);
   }

   // Get copy of the packet represented in net::packet
   rte_mbuf*
   get_packet() {
       // Fast path, consider removing it for stable code.
       return _mbuf;
   }

private:


   // Explicitly invalidate _mbuf and return the original
   // _mbuf.
   // Be extra careful!! This is used internally by different
   // devices to directly send an rte_packet. And I don't know
   // hide it from public access. User should not
   // call this function by any means.
   rte_mbuf* release_mbuf() {
       rte_mbuf* tmp = _mbuf;
       _mbuf = nullptr;
       return tmp;
   }

   // How are you going to call this constructor, if you
   // can't build a mbuf from the rte_mpool?



};

struct ips_flow_state{

    uint16_t _state[50];
    int _dfa_id[50];
    bool _alert[50];


};


void compute_gpu_processing_time(char *pkt_batch, char *state_batch, char *extra_info, int flowDim, int nflows,cudaStream_t stream){
    std::chrono::time_point<std::chrono::steady_clock> time_start;
    std::chrono::time_point<std::chrono::steady_clock> time_stop;
    time_start = steady_clock_type::now();
    gpu_launch(pkt_batch, state_batch, extra_info, flowDim, nflows,stream);
    gpu_sync(stream);
    time_stop = steady_clock_type::now();
    auto elapsed = time_stop - time_start;
    if(PRINT_TIME)  printf("GPU_Processing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
    return;
}



struct PKT{

    char pkt[MAX_PKT_SIZE];
};

class cuda_mem_allocator{
public:



    cuda_mem_allocator(){
        gpu_malloc((void**)(&dev_pkt_batch_ptr),sizeof(PKT)*GPU_BATCH_SIZE*4);
        gpu_malloc((void**)(&dev_state_batch_ptr),sizeof(ips_flow_state)*MAX_FLOW_NUM);


    }
    ~cuda_mem_allocator(){}

    PKT* gpu_pkt_batch_alloc(int size){
        if(size>GPU_BATCH_SIZE*4){
            return nullptr;
        }else{
            return dev_pkt_batch_ptr;
        }
    }
    ips_flow_state* gpu_state_batch_alloc(int size){
        if(size>MAX_FLOW_NUM){
            return nullptr;
        }else{
            return dev_state_batch_ptr;
        }
    }



    PKT* dev_pkt_batch_ptr;
    ips_flow_state* dev_state_batch_ptr;

};


class IPS{
public:
    IPS(){

        int num_patterns, i;

        int num_threads = 1;
        assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        // Map ips object
        //gpu_mem_map(this, sizeof(IPS));
        gpu_malloc((void**)(&gpu_ips), sizeof(IPS));

        //gpu map
        //gpu_mem_map(stats,num_threads * sizeof(struct stat_t));
        struct stat_t *gpu_stats;
        stats =(struct stat_t *)malloc(num_threads * sizeof(struct stat_t));
        gpu_malloc((void**)(&gpu_stats), num_threads * sizeof(struct stat_t));

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
           // gpu_mem_map(dfa_arr[i].root,AHO_MAX_STATES * sizeof(struct aho_state));
           // gpu_malloc((void**)(&dev_stats),num_threads * sizeof(struct stat_t));
           // gpu_memcpy_async_h2d(dev_stats,stats,num_threads * sizeof(struct stat_t));
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


        gpu_memcpy_async_h2d(gpu_ips, this, sizeof(IPS));

        for(i = 0; i < AHO_MAX_DFA; i++) {

            struct aho_state* gpu_root;
            int offset = (char *)&dfa_arr[i].root - (char *)this;
            char *des_addr = (char *)gpu_ips + offset;
            //printf("i = :%d, max = %d\n",i,AHO_MAX_DFA);
            gpu_malloc((void**)(&gpu_root), AHO_MAX_STATES * sizeof(struct aho_state));

            gpu_memcpy_async_h2d(gpu_root, dfa_arr[i].root, AHO_MAX_STATES * sizeof(struct aho_state));
            gpu_memcpy_async_h2d(des_addr, &gpu_root, sizeof(struct aho_state *));
        }


        gpu_memcpy_async_h2d(gpu_stats, stats, num_threads * sizeof(struct stat_t));

    }
    ~IPS(){

        for(int i = 0; i < AHO_MAX_DFA; i++) {

            //gpu_mem_unmap(dfa_arr[i].root);
            free(dfa_arr[i].root);
        }



        //gpu_mem_unmap(stats);
       // gpu_mem_unmap(this);
        free(stats);
    }
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
    IPS *gpu_ips;

};






class forwarder {

public:
    forwarder(uint16_t port_id, uint16_t queue_id) :_pkt_counter(0),_port_id(port_id),_queue_id(queue_id){

    }

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
        forwarder& _f;
        ips_flow_state _fs;
        std::vector<rte_packet> packets[2];
        bool _initialized;


        flow_operator(forwarder& f):
            _f(f)
            ,_initialized(false){

            init_automataState(_fs);
        }
        flow_operator(const flow_operator& other) = delete;
        flow_operator(flow_operator&& other) noexcept
            :_f(other._f),_fs(other._fs) ,_initialized(other._initialized){

            //for(unsigned int i=0;i<other.packets[current_idx].size();i++){
            //    packets[current_idx].push_back(std::move(other.packets[current_idx][i]));
            //}

            packets[0] = std::move(other.packets[0]);
            packets[1] = std::move(other.packets[1]);
            init_automataState(_fs);
        }
        ~flow_operator(){

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
        void process_pkt(rte_packet* pkt, ips_flow_state* fs){

            //std::cout<<"before ips_detect"<<std::endl;
            ips_detect(pkt,fs);
            //std::cout<<"after ips_detect"<<std::endl;
        }

        void forward_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){

                //std::cout<<"begin to send pkt"<<std::endl;
                _f.send_pkt(std::move(packets[index][i]));
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
                process_pkt(&packets[index][i],&_fs);

            }
            forward_pkts(index);

        }
        void update_state(uint64_t index){
            if(packets[index].empty()){   //if it is the first packets[current_idx] of this flow in this batch
                if(_initialized){    //if it has already processed previous batch, then the state is newer than remote, so update to remote.
                   /* auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                    return _f._mc.query(Operation::kSet, mica_key(key),
                            mica_value(_fs)).then([](mica_response response){
                        return make_ready_future<>();
                    });*/
                }else{              //if it is just initialized, it need get the flow state from the remote server.
                    _initialized=true;
                    /*auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
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

                    });*/
                    init_automataState(_fs);

                }
            }else{
                //return make_ready_future<>();
            }

            //return make_ready_future<>();
        }

        void run_ips(rte_packet pkt) {

                //uint64_t test_len=mbufs_per_queue_tx*inline_mbuf_size+mbuf_cache_size+sizeof(struct rte_pktmbuf_pool_private);

                //printf("pkt: %p, RX_ad: %p, TX_ad: %p, len: %ld, end_RX: %p, end_TX: %p",_ac.cur_packet().get_header<ether_hdr>(0),netstar_pools[1],netstar_pools[0],test_len,test_len+(char*)netstar_pools[1],test_len+(char*)netstar_pools[0]);
                //assert(((char*)_ac.cur_packet().get_header<ether_hdr>(0)>=(char*)netstar_pools[1]&&(char*)_ac.cur_packet().get_header<ether_hdr>(0)<=test_len+(char*)netstar_pools[1])||((char*)_ac.cur_packet().get_header<ether_hdr>(0)>=(char*)netstar_pools[0]&&(char*)_ac.cur_packet().get_header<ether_hdr>(0)<=test_len+(char*)netstar_pools[0]));

                if(_f._pkt_counter>=GPU_BATCH_SIZE&&_f._batch.need_process==true){

                    //drop
                    return _f.drop_pkt(std::move(pkt));

                 }

                //std::cout<<"pkt_num:"<<_f._pkt_counter<<std::endl;
                update_state(_f._batch.current_idx);
                                       //update the flow state when receive the first pkt of this flow in this batch.

                if(packets[_f._batch.current_idx].empty()){
                    _f._batch._flows[_f._batch.current_idx].push_back(this);
                }

                _f._pkt_counter++;
                packets[_f._batch.current_idx].push_back(std::move(pkt));

                if(_f._pkt_counter>=GPU_BATCH_SIZE&&_f._batch.need_process==false){
                     _f._batch.need_process=true;
                     _f._pkt_counter=0;
                     _f._batch.current_idx=!_f._batch.current_idx;


                 }
                if(_f._batch.need_process==true&&_f._batch.processing==false){
                    //reach batch size schedule
                    _f._batch.processing=true;
                    //std::cout<<"schedule_task"<<std::endl;

                    _f._batch.schedule_task(!_f._batch.current_idx);
                    _f._batch.need_process=false;
                    _f._batch.processing=false;
                    return;



                }else{
                    return;
                }
                //return make_ready_future<af_action>(af_action::forward);





        }

       void init_automataState(struct ips_flow_state& state){
             for(int i=0;i<50;i++){
                 srand((unsigned)time(NULL));
                 state._state[i]=0;
                 state._alert[i]=false;
                 state._dfa_id[i]=rand()%AHO_MAX_DFA;
             }


             //std::cout<<"init_automataState_dfa_id:"<<state._dfa_id<<std::endl;
         }
       void parse_pkt(rte_packet *rte_pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){

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
               int len = pkts[I].len;

               for(int times=0;times<50;times++){

                   int state = ips_state->_state[times];
                   int dfa_id = pkts[I].dfa_id[times];
                   struct aho_state *st_arr = dfa_arr[dfa_id].root;
                   if(state>=dfa_arr[dfa_id].num_used_states){
                     ips_state->_alert[times]=false;
                     ips_state->_state[times]=0;
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
                         ips_state->_alert[times]=true;
                         ips_state->_state[times]=0;

                     }
                     int inp = pkts[I].content[j];
                     state = st_arr[state].G[inp];
                 }
                 //std::cout<<"      after for loop"<<std::endl;
                 ips_state->_state[times]=state;
               }

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
       void ips_detect(rte_packet *rte_pkt, struct ips_flow_state* state){

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
           worker_cb.stats = _f.ips->stats;
           worker_cb.tot_threads = 1;
           worker_cb.tid = 0;
           worker_cb.dfa_arr = _f.ips->dfa_arr;
           worker_cb.pkts = pkts;
           worker_cb.num_pkts = 1;
           //std::cout<<"  before ids_func"<<std::endl;
           ids_func(&worker_cb,state);
           //std::cout<<"  after ids_func"<<std::endl;
           free(pkts->content);
           free(pkts);

       }

    };

    void send_pkt(rte_packet pkt){

        _send_buffer.push_back(pkt.get_packet());

        if(_send_buffer.size()==MAX_PKT_BURST){
            rte_mbuf** buf_addr=&_send_buffer[0];
            int ret=rte_eth_tx_burst(_port_id,_queue_id,buf_addr,MAX_PKT_BURST);
            if(ret<MAX_PKT_BURST){
                for(int i=ret;i<MAX_PKT_BURST;i++){
                    rte_pktmbuf_free(buf_addr[i]);
                }
            }
            _send_buffer.clear();
        }


    }

    void drop_pkt(rte_packet pkt){

        rte_pktmbuf_free(pkt.get_packet());


    }


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
        PKT* gpu_pkts[2];
        ips_flow_state* gpu_states[2];
        PKT* dev_gpu_pkts;
        ips_flow_state* dev_gpu_states;
        bool need_process;
        bool processing;
        uint64_t current_idx;
        cudaStream_t stream;
        cuda_mem_allocator _cuda_mem_allocator;
        int pre_ngpu_pkts;
        int pre_ngpu_states;
        int pre_max_pkt_num_per_flow;
        int pre_partition;


        batch():dev_gpu_pkts(nullptr),dev_gpu_states(nullptr),need_process(false),processing(false),current_idx(0),pre_ngpu_pkts(0),pre_ngpu_states(0),pre_max_pkt_num_per_flow(0),pre_partition(0){
            create_stream(&stream);

        }
        ~batch(){
            destory_stream(stream);

        }



        void schedule_task(uint64_t index){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU
            //std::cout<<"flow_size:"<<_flows[index].size()<<std::endl;
            //std::cout<<"schedule task"<<std::endl;
            stoped = steady_clock_type::now();
            auto elapsed = stoped - started;
          if(PRINT_TIME)  printf("Enqueuing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started = steady_clock_type::now();

            if(_flows[!index].empty()==false){


                gpu_memcpy_async_d2h(gpu_pkts[!index],dev_gpu_pkts,pre_ngpu_pkts,stream);
                gpu_memcpy_async_d2h(gpu_states[!index],dev_gpu_states,pre_ngpu_states,stream);

            }



            //for(unsigned int i=0;i<_flows[index].size();i=i+1){
                //std::cout<<_flows[index][i]->packets[index].size()<<" ";
            //}
            //std::cout<<"end before sort"<<std::endl;
            started = steady_clock_type::now();
            int partition=0;
            if(GPU_BATCH_SIZE!=1){
                sort(_flows[index].begin(),_flows[index].end(),CompLess);
                partition=get_partition(index);
                //partition=_flows[index].size()*5/6;
                if(PRINT_TIME)std::cout<<"Total flow_num:"<<_flows[index].size()<<std::endl;
                if(PRINT_TIME)printf("partition: %d\n",partition);
            }
            assert(partition!=-1);

            stoped = steady_clock_type::now();
            elapsed = stoped - started;
            if(PRINT_TIME)printf("Scheduling time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started = steady_clock_type::now();

            if(partition>0){

                int max_pkt_num_per_flow=_flows[index][partition-1]->packets[index].size();
                int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(PKT);
                if(PRINT_TIME)std::cout<<"ngpu_pkts:"<<ngpu_pkts/sizeof(PKT)<<std::endl;
                int ngpu_states = partition * sizeof(ips_flow_state);
                gpu_pkts[index] = (PKT*)malloc(ngpu_pkts);
                gpu_states[index] = (ips_flow_state*)malloc(ngpu_states);


                assert(gpu_pkts[index]);
                assert(gpu_states[index]);

                // Clear and map gpu_pkts and gpu_states
                memset(gpu_pkts[index], 0, ngpu_pkts);
                memset(gpu_states[index], 0, ngpu_states);
                //printf("gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);
                gpu_mem_map(gpu_pkts[index], ngpu_pkts);
                gpu_mem_map(gpu_states[index], ngpu_states);

                //std::cout<<"memory alloc finished"<<std::endl;
                for(int i = 0; i < partition; i++){
                    //gpu_states[i] = reinterpret_cast<char*>(&(_flows[index][i]->_fs));

                   // rte_memcpy(&gpu_states[index][i],&(_flows[index][i]->_fs),sizeof(ips_flow_state));
                   // assert(gpu_states[index][i]._dfa_id<200);
                    //std::cout<<"CPU: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
  //printf("cpu(): state[%d]->_dfa_id = %d\n", i, ((struct ips_flow_state *)gpu_states[i])->_dfa_id);
                    //gpu_mem_map(gpu_states[i], sizeof(struct ips_flow_state));
                    //std::cout<<"assign gpu_states["<<i<<"]"<<std::endl;
                    for(int j = 0; j < (int)_flows[index][i]->packets[index].size(); j++){

                       // gpu_pkts[i*max_pkt_num_per_flow+j]=reinterpret_cast<char*>(_flows[index][i]->packets[index][j].get_header<ether_hdr>(0));
                        rte_memcpy(gpu_pkts[index][i*max_pkt_num_per_flow+j].pkt,reinterpret_cast<char*>(_flows[index][i]->packets[index][j].get_header<ether_hdr>(0)),_flows[index][i]->packets[index][j].len());
                        //std::cout<<"assign gpu_pkts["<<i<<"]"<<"["<<j<<"]"<<std::endl;

                        // Map every packet
                        //gpu_mem_map(gpu_pkts[i*max_pkt_num_per_flow+j], _flows[index][i]->packets[index][j].len());
                    }
                }


                //sync last batch's result and copy them back to host
                if(_flows[!index].empty()==false){


                    started = steady_clock_type::now();
                    gpu_sync(stream);
                    stoped = steady_clock_type::now();
                    elapsed = stoped - started;
                    if(PRINT_TIME)  printf("Sync time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started = steady_clock_type::now();



                    for(int i = 0; i < pre_partition; i++){
                        //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                        //assert(gpu_states[!index][i]._dfa_id<200);
                        rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(ips_flow_state));

                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                        }
                    }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped = steady_clock_type::now();
                    elapsed = stoped - started;
                    if(PRINT_TIME)  printf("Copyback time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started = steady_clock_type::now();

                    // Unmap gpu_pkts and gpu_states
                    gpu_mem_unmap(gpu_pkts[!index]);
                    gpu_mem_unmap(gpu_states[!index]);

                    // Forward GPU packets[current_idx]
                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }



                    if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }
                    _flows[!index].clear();
                }


                //batch the current state
                for(int i = 0; i < partition; i++){
                    //gpu_states[i] = reinterpret_cast<char*>(&(_flows[index][i]->_fs));

                    rte_memcpy(&gpu_states[index][i],&(_flows[index][i]->_fs),sizeof(ips_flow_state));
                    //assert(gpu_states[index][i]._dfa_id<200);

                }





                pre_ngpu_pkts=ngpu_pkts;
                pre_ngpu_states=ngpu_states;
                pre_max_pkt_num_per_flow=max_pkt_num_per_flow;
                pre_partition=partition;

                dev_gpu_pkts=_cuda_mem_allocator.gpu_pkt_batch_alloc(ngpu_pkts/sizeof(PKT));
                dev_gpu_states=_cuda_mem_allocator.gpu_state_batch_alloc(ngpu_states/sizeof(ips_flow_state));
                assert(dev_gpu_pkts!=nullptr&&dev_gpu_states!=nullptr);


                stoped = steady_clock_type::now();
                elapsed = stoped - started;
                if(PRINT_TIME)printf("Batching time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                started = steady_clock_type::now();

                gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);


                stoped = steady_clock_type::now();
                elapsed = stoped - started;
                if(PRINT_TIME)printf("Memcpy to device time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                started = steady_clock_type::now();



                //printf("----gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);

                /////////////////////////////////////////////
                // Launch kernel
                //float elapsedTime = 0.0;
                //// event_start, event_stop;
                //cudaEventCreate(&event_start);
                //cudaEventCreate(&event_stop);
                //cudaEventRecord(event_start, 0);



                if(PRINT_TIME){
                    std::thread th = std::thread(compute_gpu_processing_time,(char *)dev_gpu_pkts, (char *)dev_gpu_states, (char *)(_flows[0][index]->_f.ips->gpu_ips), max_pkt_num_per_flow, partition,stream);
                    th.detach();
                }else{
                    gpu_launch((char *)dev_gpu_pkts, (char *)dev_gpu_states, (char *)(_flows[0][index]->_f.ips->gpu_ips), max_pkt_num_per_flow, partition,stream);
                }


            }else{
                if(_flows[!index].empty()==false){


                    started = steady_clock_type::now();
                    gpu_sync(stream);
                    stoped = steady_clock_type::now();
                    elapsed = stoped - started;
                    if(PRINT_TIME)  printf("Sync time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started = steady_clock_type::now();

                    for(int i = 0; i < pre_partition; i++){
                        //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                        //assert(gpu_states[!index][i]._dfa_id<200);
                        rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(ips_flow_state));

                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                        }
                    }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped = steady_clock_type::now();
                    elapsed = stoped - started;
                    if(PRINT_TIME)  printf("Copyback time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started = steady_clock_type::now();

                    // Unmap gpu_pkts and gpu_states
                    gpu_mem_unmap(gpu_pkts[!index]);
                    gpu_mem_unmap(gpu_states[!index]);

                    // Forward GPU packets[current_idx]
                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }



                    if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }
                    _flows[!index].clear();
                }
            }

            started = steady_clock_type::now();

            for(unsigned int i = partition; i < _flows[index].size(); i++){
                _flows[index][i]->process_pkts(index);
            }
            if(partition==0){
                _flows[index].clear();
            }



            stoped = steady_clock_type::now();
            elapsed = stoped - started;
            if(PRINT_TIME)printf("CPU processing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started = steady_clock_type::now();



        }
        uint64_t get_partition(uint64_t index){

            float processing_time=0;
            float min_processing_time=10000000;
            float cpu_processing_num=0;
            float pre_cpu_processing_num=0;


            for(unsigned int i=_flows[index].size();i>=0;i--){
                float cpu_time=0;
                float gpu_time=0;
                if(i>0)
                    gpu_time=_flows[index][i-1]->packets[index].size();
                for(unsigned int j=i;j<_flows[index].size();j++){
                    cpu_time+=_flows[index][j]->packets[index].size();
                }
                processing_time=std::max(gpu_time,cpu_time/COMPUTE_RATIO);
                pre_cpu_processing_num=cpu_processing_num;
                cpu_processing_num=cpu_time;
                if(processing_time>=min_processing_time){
                    if(PRINT_TIME)std::cout<<"cpu_pkts_processed: "<<pre_cpu_processing_num<<std::endl;
                    if(i==0){
                        if(PRINT_TIME)    std::cout<<"GPU_max_pkt: "<<0<<std::endl;
                        return 0;
                    }else{
                        if(PRINT_TIME)   std::cout<<"GPU_max_pkt: "<<_flows[index][i]->packets[index].size()<<std::endl;
                        return i+1;
                    }
                    //std::cout<<"    min_processing_time:"<<*result<<std::endl;


                }else{
                    min_processing_time=processing_time;
                }

            }
            return 0;
        }

    };


public:
    static IPS* ips;
    batch _batch;
    uint64_t _pkt_counter;
    uint16_t _port_id;
    uint16_t _queue_id;
    std::vector<rte_mbuf*> _send_buffer;

};










static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for(unsigned i =0; i<CORE_NUM; i++){
		total_packets_dropped += statistics[portid][i].dropped;
		total_packets_tx += statistics[portid][i].tx;
		total_packets_rx += statistics[portid][i].rx;
	}
		/* skip disabled ports */


	printf("\nStatistics for port %u ------------------------------"
		   "\nPackets sent: %24"PRIu64
		   "\nPackets received: %20"PRIu64
		   "\nPackets dropped: %21"PRIu64,
		   0,
		   total_packets_tx-pre_total_tx,
		   total_packets_rx-pre_total_rx,
		   total_packets_dropped-pre_total_drop);


	pre_total_tx=total_packets_tx;
	pre_total_drop=total_packets_dropped;
	pre_total_rx=total_packets_rx;

	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static void
l2fwd_main_loop(void)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    unsigned i, portid, nb_rx, send, queueid;
    struct lcore_conf *qconf;
    uint64_t cur_tsc,diff_tsc,prev_tsc,timer_tsc;

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];
    prev_tsc = rte_rdtsc();
    timer_tsc=0;

    if (qconf->n_rx_queue == 0) {

        return;
    }


    while (1) {


    	cur_tsc = rte_rdtsc();
        /*
         * TX burst queue drain
         */
    	diff_tsc = cur_tsc - prev_tsc;

		/* if timer is enabled */

			/* advance the timer */
		timer_tsc += diff_tsc;
		//printf("timer_period: %18"PRIu64"\n",timer_period);

		/* if timer has reached its timeout */
		if (unlikely(timer_tsc >= timer_period)) {

			/* do this only on master core */
			if (lcore_id == 0) {
				print_stats();
				/* reset the timer */

			}
			timer_tsc = 0;
		}

		prev_tsc = cur_tsc;

        /*
         * Read packet from RX queues
         */

        for (i = 0; i < qconf->n_rx_queue; i++) {

			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;


            nb_rx = rte_eth_rx_burst((uint8_t) portid, queueid,
                         pkts_burst, MAX_PKT_BURST);

            statistics[portid][lcore_id].rx+=nb_rx;



            send = rte_eth_tx_burst(portid,portid,pkts_burst,nb_rx);
            //printf("send %u pkts\n",send);
            statistics[portid][lcore_id].tx+=send;
            statistics[portid][lcore_id].dropped+=nb_rx-send;
            if(send<nb_rx){
            	for(unsigned i= send;i<nb_rx;i++){
            		rte_pktmbuf_free(pkts_burst[i]);
            	}

            }
        }
    }
}


/* main processing loop */
static int
main_loop(__attribute__((unused)) void *dummy)
{
  printf("locre\n");
  l2fwd_main_loop();
  return 0;
}

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			printf("invalid queue number: %hhu\n", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
			(numa_on == 0)) {
			printf("warning: lcore %hhu is on socket %d with numa off \n",
				lcore, socketid);
		}
	}
	return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("port %u is not enabled in port mask\n", portid);
			return -1;
		}
		if (portid >= nb_ports) {
			printf("port %u is not present on the board\n", portid);
			return -1;
		}
	}
	return 0;
}

static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port && lcore_params[i].queue_id > queue)
			queue = lcore_params[i].queue_id;
	}
	return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf ("%s [EAL options] -- -p PORTMASK -P"
		"  [--config (port,queue,lcore)[,(port,queue,lcore]]"
		"  [--enable-jumbo [--max-pkt-len PKTLEN]]\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"  -P : enable promiscuous mode\n"
		"  --config (port,queue,lcore): rx queues configuration\n"
		"  --eth-dest=X,MM:MM:MM:MM:MM:MM: optional, ethernet destination for port X\n"
		"  --no-numa: optional, disable numa awareness\n"
		"  --ipv6: optional, specify it if running ipv6 packets\n"
		"  --enable-jumbo: enable jumbo frame"
		" which max packet len is PKTLEN in decimal (64-9600)\n"
		"  --hash-entry-num: specify the hash entry number in hexadecimal to be setup\n",
		prgname);
}

static int parse_max_pkt_len(const char *pktlen)
{
	char *end = NULL;
	unsigned long len;

	/* parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}



static int
parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++){
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			printf("exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;
	return 0;
}

static void
parse_eth_dest(const char *optarg)
{
	uint8_t portid;
	char *port_end;
	uint8_t c, *dest, peer_addr[6];

	errno = 0;
	portid = strtoul(optarg, &port_end, 10);
	if (errno != 0 || port_end == optarg || *port_end++ != ',')
		rte_exit(EXIT_FAILURE,
		"Invalid eth-dest: %s", optarg);
	if (portid >= RTE_MAX_ETHPORTS)
		rte_exit(EXIT_FAILURE,
		"eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
		portid, RTE_MAX_ETHPORTS);

	if (cmdline_parse_etheraddr(NULL, port_end,
		&peer_addr, sizeof(peer_addr)) < 0)
		rte_exit(EXIT_FAILURE,
		"Invalid ethernet address: %s\n",
		port_end);
	dest = (uint8_t *)&dest_eth_addr[portid];
	for (c = 0; c < 6; c++)
		dest[c] = peer_addr[c];
	*(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
}

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{CMD_LINE_OPT_CONFIG, 1, 0, 0},
		{CMD_LINE_OPT_ETH_DEST, 1, 0, 0},
		{CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
		{CMD_LINE_OPT_IPV6, 0, 0, 0},
		{CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
		{CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:P",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			printf("Promiscuous mode selected\n");
			promiscuous_on = 1;
			break;

		/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG,
				sizeof (CMD_LINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ETH_DEST,
				sizeof(CMD_LINE_OPT_CONFIG))) {
					parse_eth_dest(optarg);
			}

			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
				sizeof(CMD_LINE_OPT_NO_NUMA))) {
				printf("numa is disabled \n");
				numa_on = 0;
			}

			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ENABLE_JUMBO,
				sizeof (CMD_LINE_OPT_ENABLE_JUMBO))) {
				struct option lenopts = {"max-pkt-len", required_argument, 0, 0};

				printf("jumbo frame is enabled - disabling simple TX path\n");
				port_conf.rxmode.jumbo_frame = 1;

				/* if no max-pkt-len set, use the default value ETHER_MAX_LEN */
				if (0 == getopt_long(argc, argvopt, "", &lenopts, &option_index)) {
					ret = parse_max_pkt_len(optarg);
					if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)){
						printf("invalid packet length\n");
						print_usage(prgname);
						return -1;
					}
					port_conf.rxmode.max_rx_pkt_len = ret;
				}
				printf("set jumbo frame max packet length to %u\n",
						(unsigned int)port_conf.rxmode.max_rx_pkt_len);
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}



static int
init_mem(unsigned nb_mbuf)
{
	struct lcore_conf *qconf;
	int socketid;
	unsigned lcore_id;
	char s[64];

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
				socketid, lcore_id, NB_SOCKETS);
		}
		if (pktmbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] =
				rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
						"Cannot init mbuf pool on socket %d\n", socketid);
			else
				printf("Allocated mbuf pool on socket %d\n", socketid);

		}
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = ipv4_l3fwd_lookup_struct[socketid];
		qconf->ipv6_lookup_struct = ipv6_l3fwd_lookup_struct[socketid];
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
main(int argc, char **argv)
{

	gettimeofday(&tv,NULL);
	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.header_split   = 0;
	port_conf.rxmode.hw_ip_checksum = 1;
	port_conf.rxmode.hw_vlan_filter = 0;
	port_conf.rxmode.jumbo_frame    = 0;
	port_conf.rxmode.hw_strip_crc   = 0;
	port_conf.rx_adv_conf.rss_conf.rss_key   = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
	port_conf.txmode.mq_mode=ETH_MQ_TX_NONE;


	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	unsigned nb_ports;
	uint16_t queueid;
	unsigned lcore_id;
	uint32_t n_tx_queue, nb_lcores;
	uint8_t portid, nb_rx_queue, queue, socketid;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	/* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		dest_eth_addr[portid] = ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
		*(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
	}
	timer_period =rte_get_timer_hz();

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	if (check_port_config(nb_ports) < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	nb_lcores = rte_lcore_count();

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", portid );
		fflush(stdout);

		nb_rx_queue = get_port_n_rx_queues(portid);
		n_tx_queue = nb_lcores;
		if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
			n_tx_queue = MAX_TX_QUEUE_PER_PORT;
		printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
			nb_rx_queue, (unsigned)n_tx_queue );
		ret = rte_eth_dev_configure(portid, nb_rx_queue,
					(uint16_t)n_tx_queue, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
				ret, portid);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		printf(", ");
		print_ethaddr("Destination:",
			(const struct ether_addr *)&dest_eth_addr[portid]);
		printf(", ");

		/*
		 * prepare src MACs for each port.
		 */
		ether_addr_copy(&ports_eth_addr[portid],
			(struct ether_addr *)(val_eth + portid) + 1);

		/* init memory */
		ret = init_mem(NB_MBUF);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "init_mem failed\n");

		/* init one TX queue per couple (lcore,port) */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			if (numa_on)
				socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
			fflush(stdout);

			rte_eth_dev_info_get(portid, &dev_info);
			txconf = &dev_info.default_txconf;
			if (port_conf.rxmode.jumbo_frame)
				txconf->txq_flags = 0;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     socketid, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
					"port=%d\n", ret, portid);

			qconf = &lcore_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;
		}
		printf("\n");
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];
		printf("\nInitializing rx queues on lcore %u ... ", lcore_id );
		fflush(stdout);
		/* init RX queues */
		for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			if (numa_on)
				socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;

			printf("rxq=%d,%d,%d ", portid, queueid, socketid);
			fflush(stdout);

			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
					socketid,
					NULL,
					pktmbuf_pool[socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d,"
						"port=%d\n", ret, portid);
		}
	}

	printf("\n");

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
