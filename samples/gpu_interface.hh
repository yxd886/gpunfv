#ifndef GPU_INTERFACE_HH
#define GPU_INTERFACE_HH

void gpu_launch(char *pkt_batch, char *state_batch, char *extra_info, int flowDim, int nflows,cudaStream_t stream);
void gpu_sync(cudaStream_t stream);
void gpu_mem_map(void *ptr, size_t size);
void gpu_mem_unmap(void *ptr);

void gpu_malloc(void** devPtr, size_t size);
void gpu_memcpy_async_h2d(void* dst, const void*src, size_t count, cudaStream_t stream=0  );

void gpu_memcpy_async_d2h(void* dst, const void*src, size_t count, cudaStream_t stream=0 );

void gpu_memset_async(void * devPtr, int value, size_t count, cudaStream_t stream = 0);

void gpu_free(void* devPtr);

void create_stream(cudaStream_t* stream_ptr);

void gpu_free_host(void* hostPtr);
void gpu_malloc_host(void** hostPtr, size_t size);

void destory_stream(cudaStream_t stream);

#endif
