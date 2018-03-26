#ifndef PLAYGROUND_HH
#define PLAYGROUND_HH

void gpu_launch(char **pkt_batch, char **state_batch, char *extra_info, int flowDim, int nflows);
void gpu_sync();
void gpu_mem_map(void *ptr, size_t size);
void gpu_mem_unmap(void *ptr);

#endif