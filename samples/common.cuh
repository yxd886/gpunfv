#ifndef COMMON_CUH
#define COMMON_CUH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <netinet/ip.h>
#include <rte_ether.h>

using namespace std;

#define BigLittleSwap16(A)  ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define BigLittleSwap32(A)  ((((uint32_t)(A) & 0xff000000) >> 24) | (((uint32_t)(A) & 0x00ff0000) >> 8) | \
                            (((uint32_t)(A) & 0x0000ff00) << 8) | (((uint32_t)(A) & 0x000000ff) << 24))

__device__ bool checkCPUendian() {
	union{
		uint32_t i;
		unsigned char s[4];
	} c;

   c.i = 0x12345678;
   return (0x12 == c.s[0]);
}

__device__ uint32_t Htonl(uint32_t h) {
	return checkCPUendian() ? h : BigLittleSwap32(h);
}

__device__ uint32_t Ntohl(uint32_t n) {
	return checkCPUendian() ? n : BigLittleSwap32(n);
}

__device__ uint16_t Htons(uint16_t h) {
	return checkCPUendian() ? h : BigLittleSwap16(h);
}

__device__ uint16_t Ntohs(uint16_t n) {
	return checkCPUendian() ? n : BigLittleSwap16(n);
}

__device__ uint32_t pkt_len(void *pkt) {
	//struct ether_hdr* m_pEthhdr = (struct ether_hdr*)pkt;
	struct iphdr* m_pIphdr = (struct iphdr*)(pkt + sizeof(struct ether_hdr));

  return Ntohs(m_pIphdr->tot_len) + sizeof(struct ether_hdr);
}

#endif