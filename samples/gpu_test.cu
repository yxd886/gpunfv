#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cuda_runtime.h>
#include <helper_cuda.h>
#include "gpu_ips.cuh"

using namespace std;

#define THREADPERBLOCK	256
#define SHARE_MEM_SIZE  256

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

__global__ void gpu_nf_logic(char** pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows) {
	//printf("in gpu_nf_logic\n");
	int id = threadIdx.x + blockDim.x * blockIdx.x;
	if(id >= nflows) return ;

	// Get start address
	char**pkts =pkt_batch + id * flowDim;
	//struct ips_flow_state* state_ptr=(struct ips_flow_state*)state_batch;

	//printf("pkt_batch = %x\n", pkt_batch);

	
	//printf("flowDim = %d, id = %d\n", flowDim, id);
	// For every packet for this flow in this batch
	int i=0;
	for(i= 0; i < flowDim; i++) {
	//printf("id = %d, i = %d, pkts[i] = %p\n", id, i, pkts[i]);	
		if(pkts[i] == NULL) break;
 //printf("gpu_nf_logic(): state->_dfa_id = %d\n", ((struct ips_flow_state *)state_batch[id])->_dfa_id);
		//gpu_nf_logic_impl(pkts[i], state_batch[id]);

		//ips_detect((char*)pkts[i].pkt, &state_ptr[id], (struct gpu_IPS *)extra_info);
		ips_detect(pkts[i], (struct ips_flow_state *)state_batch[id], (struct gpu_IPS *)extra_info);

//	printf("id = %d, end\n", id);	
	}
	//printf(" *%d* ", i);
	//printf("GPU: gpu_states[%d].dfa_id: %d\n",id,state_ptr[id]._dfa_id);
}

void gpu_launch(char **pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows,cudaStream_t stream) {
	// Calculate block amounts
	assert(nflows > 0);
	int nblocks = (nflows + THREADPERBLOCK - 1) / THREADPERBLOCK;
//printf("nblocks = %d, nthread = %d, nflows = %d\n", nblocks, THREADPERBLOCK, nflows);
	gpu_nf_logic<<<nblocks, THREADPERBLOCK, SHARE_MEM_SIZE, stream>>>(pkt_batch, state_batch, extra_info, flowDim, nflows);
	//gpu_nf_logic<<<1, 1, SHARE_MEM_SIZE, stream>>>(pkt_batch, state_batch, extra_info, flowDim, nflows);
}

void gpu_sync(cudaStream_t stream) {
	checkCudaErrors(cudaStreamSynchronize(stream));
}

void gpu_mem_map(void *ptr, size_t size) {
	checkCudaErrors(cudaHostRegister(ptr, size, cudaHostRegisterMapped));
}

void gpu_mem_unmap(void *ptr) {
	checkCudaErrors(cudaHostUnregister(ptr));
}

void gpu_malloc(void** devPtr, size_t size){
	checkCudaErrors(cudaMalloc(devPtr, size));
}


void gpu_memcpy_async_h2d(void* dst, const void*src, size_t count ,cudaStream_t stream=0){
	checkCudaErrors(cudaMemcpyAsync(dst,src,count,cudaMemcpyHostToDevice,stream));
}

void gpu_memcpy_async_d2h(void* dst, const void*src, size_t count, cudaStream_t stream=0 ){
	checkCudaErrors(cudaMemcpyAsync(dst,src,count,cudaMemcpyDeviceToHost,stream));
	
}


void gpu_memset_async(void * devPtr, int value, size_t count, cudaStream_t stream = 0){

	checkCudaErrors(cudaMemsetAsync(devPtr,value,count,stream))	;
}

void gpu_free(void* devPtr){
	checkCudaErrors(cudaFree(devPtr));
}




void create_stream(cudaStream_t* stream_ptr){

	checkCudaErrors(cudaStreamCreate(stream_ptr));
}

void destory_stream(cudaStream_t stream){

checkCudaErrors(cudaStreamDestroy(stream));
}