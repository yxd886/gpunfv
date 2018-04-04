/*
 * cuda_mem.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef SAMPLES_L2_FORWARD_CUDA_MEM_HH_
#define SAMPLES_L2_FORWARD_CUDA_MEM_HH_



class cuda_mem_allocator{
public:



    cuda_mem_allocator(){
        gpu_malloc((void**)(&dev_pkt_batch_ptr),sizeof(PKT)*GPU_BATCH_SIZE*40);
        gpu_malloc((void**)(&dev_state_batch_ptr),sizeof(ips_flow_state)*MAX_FLOW_NUM);



    }
    ~cuda_mem_allocator(){}

    PKT* gpu_pkt_batch_alloc(int size){
        if(size>GPU_BATCH_SIZE*40){
            return nullptr;
        }else{
            return dev_pkt_batch_ptr;
        }
    }
    ips_flow_state* gpu_state_batch_alloc(int size){
        if(size>MAX_FLOW_NUM){
            return nullptr;
        }else{
            return dev_state_batch_ptr;
        }
    }



    PKT* dev_pkt_batch_ptr;
    ips_flow_state* dev_state_batch_ptr;

};





#endif /* SAMPLES_L2_FORWARD_CUDA_MEM_HH_ */
