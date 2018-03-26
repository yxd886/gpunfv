#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cuda_runtime.h>
#include <helper_cuda.h>

using namespace std;

__global__ void testKernel(char *s) {
	int i = threadIdx.x;
	
	memcpy(s + i + 5, s + i, 1);
	assert(1);
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
	assert(hptr1);

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

int main() {
	start_test();

	return 0;
}