/*
 *  cuda_common.hh
 *
 *  Created on: Apr 17, 2018
 *      Author: Junjie Wang
 */

#ifndef CUDA_COMMON_HH
#define CUDA_COMMON_HH

// When CPU codes include this file, do not define __DEVICE__, __HOST__, __GLOBAL__
#ifndef __CUDA__

#include <cstdint>

#define __DEVICE__
#define __HOST__
#define __GLOBAL__

#else

#define __DEVICE__	__device__
#define __HOST__	__host__
#define __GLOBAL__	__global__

#endif	//__CUDA__


#endif	// CUDA_COMMON_HH