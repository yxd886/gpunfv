/*
 * l2_forward.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef SAMPLES_L2_FORWARD_L2_FORWARD_HH_
#define SAMPLES_L2_FORWARD_L2_FORWARD_HH_

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

#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>


#include <helper_functions.h>
#include <helper_cuda.h>
#include <cuda_runtime.h>
#include <cuda_profiler_api.h>
#include "../gpu_interface.hh"
#include <chrono>
#include <thread>
#include <iostream>
#include <vector>
#include <unordered_map>

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
#define ENABLE_MULTI_BUFFER_OPTIMIZE    0
#else
#define ENABLE_MULTI_BUFFER_OPTIMIZE    1
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

#define NB_MBUF RTE_MAX (                                                                   \
                (nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +                            \
                nb_ports*nb_lcores*MAX_PKT_BURST +                                          \
                nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +                              \
                nb_lcores*MEMPOOL_CACHE_SIZE),                                              \
                (unsigned)81920)

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST    (MAX_PKT_BURST / 2)

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/* Used to mark destination port as 'invalid'. */
#define BAD_PORT    ((uint16_t)-1)

#define FWDSTEP 4

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 512




/* replace first 12B of the ethernet header. */
#define MASK_ETH    0x3f



#if (APP_LOOKUP_METHOD == APP_LOOKUP_EXACT_MATCH)
static int ipv6 = 0; /**< ipv6 is false by default. */
#endif


#define MAX_MATCH 8192

struct port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
} __rte_cache_aligned;



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





void send_brust(uint8_t _port_id, uint8_t _queue_id, uint16_t lcore_id, rte_mbuf** pkt_buffer);



uint16_t receive_burst(uint8_t _port_id, uint8_t _queue_id, uint16_t lcore_id, rte_mbuf** pkt_buffer);



int check_lcore_params(void);

int check_port_config(const unsigned nb_ports);

uint8_t get_port_n_rx_queues(const uint8_t port);

int init_lcore_rx_queues(void);

/* display usage */
void print_usage(const char *prgname);

int parse_max_pkt_len(const char *pktlen);

int parse_portmask(const char *portmask);



int parse_config(const char *q_arg);

void parse_eth_dest(const char *optarg);

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"

/* Parse the argument given in the command line of the application */
int parse_args(int argc, char **argv);

void print_ethaddr(const char *name, const struct ether_addr *eth_addr);

/*static void
my_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
        void *obj, unsigned i)
{
    gpu_mem_map(obj,mp->elt_size);
    //struct rte_mbuf* rte_pkt=(struct rte_mbuf*)obj;
    //unsigned char *t =rte_pktmbuf_mtod(rte_pkt, unsigned char*);
    //char* raw_packet = (char*)t;
    //printf("obj_addr:%p\n",obj);
   // printf("raw_packet_addr:%p\n",raw_packet);
    //std::cout<<"sizeof bool:"<<sizeof(bool)<<std::endl;

}*/


int init_mem(unsigned nb_mbuf);


/* Check the link status of all ports in up to 9s, and print them finally */
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);
void print_stats(void);



void dpdk_config(int argc, char** argv);

#endif /* SAMPLES_L2_FORWARD_L2_FORWARD_HH_ */
