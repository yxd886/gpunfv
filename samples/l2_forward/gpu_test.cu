#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cuda_runtime.h>
#include <helper_cuda.h>
#include "nf.cuh"

using namespace std;

#define THREADPERBLOCK	256
#define SHARE_MEM_SIZE  512
#define MAX_PKT_SIZE 64

struct PKT{
	char pkt[MAX_PKT_SIZE];
};

__global__ void gpu_nf_logic(char* pkt_batch, char *state_batch, char *extra_info, int flowDim, int nflows) {

	__shared__ struct ips_flow_state gpu_ips_flow_state[32];

	
	int id = threadIdx.x + blockDim.x * blockIdx.x;
	if(id >= nflows) return ;

	PKT*pkts =(PKT*)pkt_batch + id * flowDim;
	struct ips_flow_state* state_ptr=(struct ips_flow_state*)state_batch;


	// for(int i= 0 ;i <DFA_NUM; i++){
	// 	gpu_ips_flow_state[id%32]._state[i]= state_ptr[id]._state[i];
	// 	gpu_ips_flow_state[id%32]._dfa_id[i] = state_ptr[id]._dfa_id[i];
	// 	gpu_ips_flow_state[id%32]._alert[i] = state_ptr[id]._alert[i];

	// }
	
	
	for(int i = 0; i < flowDim; i++) {
		if(pkts[i].pkt[0] == 0) {
			int j;
			for(j = 1; j < 14; j++) {
				if(pkts[i].pkt[j] == 0)
					break;
			}
			if(j != 14) // the whole Ethernet header is empty, means a empty packet, break the loop
				break;
		}
 			
		//NF::nf_logic((char*)pkts[i].pkt, &gpu_ips_flow_state[id%32], ((struct gpu_IPS *)extra_info)->dfa_arr);
		NF::nf_logic((char*)pkts[i].pkt, &state_ptr[id], ((struct gpu_IPS *)extra_info)->dfa_arr);
	}
	
	// for(int i= 0 ;i <DFA_NUM; i++){
	// 	state_ptr[id]._state[i]= gpu_ips_flow_state[id%32]._state[i];
	// 	state_ptr[id]._dfa_id[i]= gpu_ips_flow_state[id%32]._dfa_id[i];
	// 	state_ptr[id]._alert[i] = gpu_ips_flow_state[id%32]._alert[i];

	// }

	return;	
	

}

void gpu_launch(char *pkt_batch, char *state_batch, char *extra_info, int flowDim, int nflows,cudaStream_t stream) {
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

void gpu_malloc_host(void** devPtr, size_t size){
	checkCudaErrors(cudaHostAlloc(devPtr, size,cudaHostAllocMapped));
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


void gpu_free_host(void* devPtr){
	checkCudaErrors(cudaFreeHost(devPtr));
}




void create_stream(cudaStream_t* stream_ptr){

	checkCudaErrors(cudaStreamCreateWithFlags(stream_ptr,cudaStreamNonBlocking));
}

void destory_stream(cudaStream_t stream){

checkCudaErrors(cudaStreamDestroy(stream));
}

void create_event(cudaEvent_t* event_ptr){

checkCudaErrors(cudaEventCreateWithFlags(event_ptr,cudaEventDisableTiming));
}


