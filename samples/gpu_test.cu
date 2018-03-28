#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cuda_runtime.h>
#include <helper_cuda.h>
#include "gpu_ips.cuh"

using namespace std;

#define THREADPERBLOCK	256

__global__ void testKernel(char *s) {
	int i = threadIdx.x;
	
	memcpy(s + i + 5, s + i, 1);
	//assert(1);
}

bool test_cudaHostAlloc() {
	bool res = true;
	char *dptr1, *hptr1;

	// First way: using cudaHostAlloc()
	// Alloc host page-locked memory
	checkCudaErrors(cudaHostAlloc(&hptr1, 10, cudaHostAllocMapped));

	// Get corresponding device pointer
	checkCudaErrors(cudaHostGetDevicePointer(&dptr1, hptr1, 0));

	// Initialize this memory
	for(int i = 0; i < 5; i++)
		hptr1[i] = i;
	for(int i = 5; i < 10; i++)
		hptr1[i] = 0;

	// Test kernel
	testKernel<<<1, 5>>>(dptr1);
	cudaDeviceSynchronize();

	// Check result
	for(int i = 0; i < 10; i++){
		printf("s[%d]: %d\n", i, hptr1[i]);
		res = (hptr1[i] == i % 5) ? res : false;
	}

	// Free memory
	checkCudaErrors(cudaFreeHost(hptr1));

	return res;
}

bool test_cudaHostRegister() {
	bool res = true;
	char *dptr1, *hptr1;

	// Second way: using cudaHostRegister()
	// Alloc host memory
	hptr1 = new char[10];
	//assert(hptr1);

	// Page-lock host memory
	cudaHostRegister(hptr1, 10, cudaHostRegisterMapped);

	// Get corresponding device pointer
	checkCudaErrors(cudaHostGetDevicePointer(&dptr1, hptr1, 0));

	// Initialize this memory
	for(int i = 0; i < 5; i++)
		hptr1[i] = i;
	for(int i = 5; i < 10; i++)
		hptr1[i] = 0;

	// Test kernel
	if(cudaDevAttrCanUseHostPointerForRegisteredMem != 0){
		printf("Can directly use host pointer to substitute device pointer on this machine.\n");
		testKernel<<<1, 5>>>(hptr1);
	}
	else{
		printf("This machine does not support substituting host pointer for device pointer.\n");
		testKernel<<<1, 5>>>(dptr1);
	}
	cudaDeviceSynchronize();

	// Check result
	for(int i = 0; i < 10; i++){
		printf("s[%d]: %d\n", i, hptr1[i]);
		res = (hptr1[i] == i % 5) ? res : false;
	}

	// Free memory
	cudaHostUnregister(hptr1);
	delete hptr1;

	return res;
}

void start_test() {
	// Enable memory mapping
	cudaSetDeviceFlags(cudaDeviceMapHost);

	if(test_cudaHostAlloc())
		printf("cudaHostAlloc(): PASS\n");
	else
		printf("cudaHostAlloc(): ERROR\n");

	if(test_cudaHostRegister())
		printf("cudaHostRegister(): PASS\n");
	else
		printf("cudaHostRegister(): ERROR\n");
}

__global__ void gpu_nf_logic(char **pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows) {
	//printf("in gpu_nf_logic\n");
	int id = threadIdx.x + blockDim.x * blockIdx.x;
	if(id >= nflows) return ;

	// Get start address
	char **pkts = pkt_batch + id * flowDim;

	//printf("pkt_batch = %x\n", pkt_batch);
	
	//printf("flowDim = %d, id = %d, pkts = %p, pkts[0] = %p\n", flowDim, id, pkts, pkts[0]);
	// For every packet for this flow in this batch
	for(int i = 0; i < flowDim; i++) {
	//printf("id = %d, i = %d, pkts[i] = %p\n", id, i, pkts[i]);	
		if(pkts[i] == NULL) break;
 //printf("gpu_nf_logic(): state->_dfa_id = %d\n", ((struct ips_flow_state *)state_batch[id])->_dfa_id);
		//gpu_nf_logic_impl(pkts[i], state_batch[id]);
		ips_detect(pkts[i], (struct ips_flow_state *)state_batch[id], (struct gpu_IPS *)extra_info);
	printf("id = %d, end", id);	
	}
}

void gpu_launch(char **pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows) {
	// Calculate block amounts
	assert(nflows > 0);
	int nblocks = (nflows + THREADPERBLOCK - 1) / THREADPERBLOCK;
//printf("nblocks = %d, nthread = %d, nflows = %d\n", nblocks, THREADPERBLOCK, nflows);
	//gpu_nf_logic<<<nblocks, THREADPERBLOCK>>>(pkt_batch, state_batch, extra_info, flowDim, nflows);
	gpu_nf_logic<<<1, 1>>>(pkt_batch, state_batch, extra_info, flowDim, nflows);
}

void gpu_sync() {
	checkCudaErrors(cudaDeviceSynchronize());
}

void gpu_mem_map(void *ptr, size_t size) {
	checkCudaErrors(cudaHostRegister(ptr, size, cudaHostRegisterMapped));
}

void gpu_mem_unmap(void *ptr) {
	checkCudaErrors(cudaHostUnregister(ptr));
}