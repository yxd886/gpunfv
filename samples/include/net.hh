/*
 *  net.hh
 *
 *  Created on: Apr 17, 2018
 *      Author: Junjie Wang
 */

#ifndef NET_HH
#define NET_HH

#include "cuda_common.hh"

#define ANY_ADDR		0x00000000
#define ANY_PORT		0x0000
#define ANY_PROTOCOL	0x00

class net {
public:
	__DEVICE__ static uint32_t myntohl(uint32_t const net) {
		uint8_t *data = (uint8_t *) &net;

		return 	((uint32_t) data[3] << 0) |
				((uint32_t) data[2] << 8) |
				((uint32_t) data[1] << 16) |
				((uint32_t) data[0] << 24); 
	}

	__DEVICE__ static uint32_t myhtonl(uint32_t const host) {
		uint32_t net;
		uint8_t *data = (uint8_t *) &net;

		data[3] = host & 0xff;
		data[2] = (host >> 8) & 0xff;
		data[1] = (host >> 16) & 0xff;
		data[0] = (host >> 24) & 0xff;

		return 	net; 
	}

	__DEVICE__ static uint16_t myntohs(uint16_t const net) {
		uint8_t *data = (uint8_t *) &net;

		return 	((uint16_t) data[1] << 0) |
				((uint16_t) data[0] << 8);
	}

	__DEVICE__ static uint16_t myhtons(uint16_t const host) {
		uint16_t net;
		uint8_t *data = (uint8_t *) &net;

		data[1] = host & 0xff;
		data[0] = (host >> 8) & 0xff;

		return 	net; 
	}
};

#endif	// NET_HH