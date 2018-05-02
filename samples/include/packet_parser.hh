/*
 *  packet_parser.hh
 *
 *  Created on: Apr 17, 2018
 *      Author: Junjie Wang
 */

#ifndef PACKET_PARSER_HH
#define PACKET_PARSER_HH

#include <cassert>
#include <cstdio>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_prefetch.h>

#include "cuda_common.hh"
#include "net.hh"

struct packetInfo {
	ether_hdr *_eth_hdr;		// Ethernet header
	union {
		ipv4_hdr *_ipv4_hdr;	// ipv4 header
		ipv6_hdr *_ipv6_hdr;	// ipv6 header
	};
	union {
		tcp_hdr *_tcp_hdr;		// TCP header
		udp_hdr *_udp_hdr;		// UDP header
	};
	char *_data;				// Application layer payload
	enum {TCP = 6, UDP = 17};	// protocol id type
	uint8_t _protocol;			// Transport layer protocol type
	uint16_t _size;				// packet size
};

class packetParser {
public:
	__DEVICE__ static inline uint16_t get_size(void *packet) {
		ipv4_hdr *_ipv4_hdr = reinterpret_cast<ipv4_hdr *>((uint8_t *)packet + sizeof(ether_hdr));

		return net::myntohs(_ipv4_hdr->total_length) + sizeof(ether_hdr);
	}

	__DEVICE__ static inline void parse_ether_packet(void *packet, packetInfo *info) {
		info->_eth_hdr = reinterpret_cast<ether_hdr *>(packet);		// Ethernet header at the begining

		parse_ipv4_packet(info->_eth_hdr + 1, info);
	}

	__DEVICE__ static inline void parse_ipv4_packet(void *packet, packetInfo *info) {
		info->_ipv4_hdr = reinterpret_cast<ipv4_hdr *>(packet);		// followed by ipv4 header

		// Get ipv4 packet size
		uint16_t ipv4_size = net::myntohs(info->_ipv4_hdr->total_length);

		// Calculate total packet size
		info->_size = ipv4_size + sizeof(ether_hdr);	// sizeof(ether_hdr) should be 14 in IEEE 802.3

		// Get transport layer protocol type
		info->_protocol = info->_ipv4_hdr->next_proto_id;

		if(info->_protocol == packetInfo::TCP) {		// TCP protocol
			parse_tcp_packet(info->_ipv4_hdr + 1, info);
		}
		else if(info->_protocol == packetInfo::UDP)	{	// UDP protocol
			parse_udp_packet(info->_ipv4_hdr + 1, info);
		}
		else {
			assert(0 && "Unsupported protocol type.");
		}
	}

	__DEVICE__ static inline void parse_tcp_packet(void *packet, packetInfo *info) {
		info->_tcp_hdr = reinterpret_cast<tcp_hdr *>(packet);
		// ...
	}	

	__DEVICE__ static inline void parse_udp_packet(void *packet, packetInfo *info) {
		info->_udp_hdr = reinterpret_cast<udp_hdr *>(packet);
		// ...
	}

	__DEVICE__ static inline void parse_raw_packet(void *packet, packetInfo *info) {
		assert(packet);
		assert(info);

		parse_ether_packet(packet, info);
	}

	__DEVICE__ static void test_packet_parser(unsigned char *p) {
		printf("packet content:\n");
        for(int i = 0; i < 60; i++){
            printf("%02x ", p[i]);
            if(i % 16 == 15) printf("\n");
        }
        printf("\n");

		printf("----test_packet_parser----\n");
        packetInfo info;
        packetParser::parse_raw_packet(p, &info);

        printf("Ether: ");
        p = (unsigned char *)info._eth_hdr;
        for(int i = 0; i < sizeof(ether_hdr); i++){
            printf("%02x ", p[i]);
            if(i % 16 == 15) printf("\n");
        }
        printf("\n");

        printf("ipv4: ");
        p = (unsigned char *)info._ipv4_hdr;
        for(int i = 0; i < sizeof(ipv4_hdr); i++){
            printf("%02x ", p[i]);
            if(i % 16 == 15) printf("\n");
        }
        printf("\n");

        printf("protocol: %u\n", info._protocol);
        printf("tcp / udp: ");
        p = (info._protocol == packetInfo::TCP) ? (unsigned char *)info._tcp_hdr : (unsigned char *)info._udp_hdr;
        int size = (info._protocol == packetInfo::TCP) ? sizeof(tcp_hdr) : sizeof(udp_hdr);
        for(int i = 0; i < size; i++){
            printf("%02x ", p[i]);
            if(i % 16 == 15) printf("\n");
        }
        printf("----------test end---------\n");
	}

};

#endif	//PACKET_PARSER_HH
