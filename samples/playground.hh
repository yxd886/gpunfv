#ifndef PLAYGROUND_HH
#define PLAYGROUND_HH



constexpr uint16_t default_ring_size      = 512;

//
// We need 2 times the ring size of buffers because of the way PMDs
// refill the ring.
//
constexpr uint16_t mbufs_per_queue_rx     = 2 * default_ring_size;
constexpr uint16_t rx_gc_thresh           = 64;

//
// No need to keep more descriptors in the air than can be sent in a single
// rte_eth_tx_burst() call.
//
constexpr uint16_t mbufs_per_queue_tx     = 2 * default_ring_size;

constexpr uint16_t mbuf_cache_size        = 512;
constexpr uint16_t mbuf_overhead          =
                                 sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
//
// We'll allocate 2K data buffers for an inline case because this would require
// a single page per mbuf. If we used 4K data buffers here it would require 2
// pages for a single buffer (due to "mbuf_overhead") and this is a much more
// demanding memory constraint.
//
static constexpr size_t   inline_mbuf_data_size  = 2048;

constexpr uint16_t inline_mbuf_size       =
                                inline_mbuf_data_size + mbuf_overhead;

void gpu_launch(char **pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows,cudaStream_t stream);
void gpu_sync(cudaStream_t stream);
void gpu_mem_map(void *ptr, size_t size);
void gpu_mem_unmap(void *ptr);
void gpu_malloc(void** devPtr, size_t size);
void gpu_memcpy_async_h2d(void* dst, const void*src, size_t count, cudaStream_t stream=0  );

void gpu_memcpy_async_d2h(void* dst, const void*src, size_t count, cudaStream_t stream=0 );

void gpu_free(void* devPtr);

void create_stream(cudaStream_t* stream_ptr);

void destory_stream(cudaStream_t stream);

#endif
