#ifndef FORWARDER_HH
#define FORWARDER_HH

#include "nf.hh"
#include <omp.h>
#include <future>
#include "../gpu_interface.hh"

extern uint64_t _batch_size;
extern uint64_t print_time;
extern uint64_t gpu_time;
extern uint64_t print_simple_time;
extern uint64_t schedule_timer_tsc;

#define COMPUTE_RATIO 100
#define MAX_PKT_SIZE 64
#define MAX_FLOW_NUM 40000
#define MAX_GPU_THREAD 5
#define THREADPERBLOCK  256

std::chrono::time_point<std::chrono::steady_clock> started[10];
std::chrono::time_point<std::chrono::steady_clock> stoped[10];
std::chrono::time_point<std::chrono::steady_clock> simple_started[10];
std::chrono::time_point<std::chrono::steady_clock> simple_stoped[10];
using namespace std::chrono;
using steady_clock_type = std::chrono::steady_clock;

struct PKT{
    char pkt[MAX_PKT_SIZE];
};

class cuda_mem_allocator {
public:
    PKT* dev_pkt_batch_ptr;
    nf_flow_state* dev_state_batch_ptr;

    cuda_mem_allocator(){
        gpu_malloc((void**)(&dev_pkt_batch_ptr),sizeof(PKT)*_batch_size*40);
        gpu_malloc((void**)(&dev_state_batch_ptr),sizeof(nf_flow_state)*MAX_FLOW_NUM);
    }

    ~cuda_mem_allocator(){}

    PKT* gpu_pkt_batch_alloc(int size) {
        if(size>_batch_size*40) {
            return nullptr;
        }else{
            return dev_pkt_batch_ptr;
        }
    }

    nf_flow_state* gpu_state_batch_alloc(int size) {
        if(size>MAX_FLOW_NUM) {
            return nullptr;
        } else {
            return dev_state_batch_ptr;
        }
    }

};

static void batch_copy2device(PKT*dev_gpu_pkts,PKT* host_gpu_pkts,int ngpu_pkts, cudaStream_t stream, nf_flow_state*dev_gpu_states,nf_flow_state*host_gpu_states,int ngpu_states){
    gpu_memcpy_async_h2d(dev_gpu_pkts,host_gpu_pkts,ngpu_pkts,stream);
    gpu_memcpy_async_h2d(dev_gpu_states,host_gpu_states,ngpu_states,stream);
}

class forwarder {
public:
    forwarder(uint16_t port_id, uint16_t queue_id, uint16_t _lcore_id) :_pkt_counter(0),
        _port_id(port_id),_queue_id(queue_id),_lcore_id(_lcore_id){

    }
    enum process_type{
        hybernate,
        cpu_only
    };

    struct query_key {
        uint64_t v1;
        uint64_t v2;
    };

    class flow_operator {
    public:
        forwarder& _f;

        // nf_flow_state _fs;
        nf_flow_state _fs;

        std::vector<rte_packet> packets[2];
        bool _initialized;

        flow_operator(forwarder& f):
            _f(f)
            ,_initialized(false){

            _nf->init_automataState(_fs);
        }
        flow_operator(const flow_operator& other) = delete;
        flow_operator(flow_operator&& other) noexcept
            :_f(other._f),_fs(other._fs) ,_initialized(other._initialized){
            packets[0] = std::move(other.packets[0]);
            packets[1] = std::move(other.packets[1]);
            _nf->init_automataState(_fs);
        }
        ~flow_operator() {}

        void post_process(){
            _f._pkt_counter-=packets[_f._batch.current_idx].size();
            assert(_f._pkt_counter>=0);
            process_pkts(_f._batch.current_idx);

            std::vector<flow_operator*>::iterator it;
            for(it=_f._batch._flows[_f._batch.current_idx].begin();it!=_f._batch._flows[_f._batch.current_idx].end();it++){
                if(*it==this){
                    _f._batch._flows[_f._batch.current_idx].erase(it);
                    break;
                }
            }
        }

        void forward_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){
                _f.send_pkt(std::move(packets[index][i]));
            }
            packets[index].clear();
            assert(packets[index].size()==0);
        }

        void process_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){
                process_pkt(&packets[index][i],&_fs);
            }
            forward_pkts(index);
        }

        void process_pkt(rte_packet* pkt, nf_flow_state* fs){
            _nf->nf_logic(pkt, fs);
            //IPS::ips_detect(pkt,fs);
        }

        void update_state(uint64_t index){
            if(packets[index].empty()){   //if it is the first packets[current_idx] of this flow in this batch
                if(_initialized){    //if it has already processed previous batch, then the state is newer than remote, so update to remote.
                   /* auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                    return _f._mc.query(Operation::kSet, mica_key(key),
                            mica_value(_fs)).then([](mica_response response){
                        return make_ready_future<>();
                    });*/
                }else{              //if it is just initialized, it need get the flow state from the remote server.
                    _initialized=true;
                    /*auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                    return _f._mc.query(Operation::kGet, mica_key(key),
                            mica_value(0, temporary_buffer<char>())).then([this](mica_response response){
                        if(response.get_result() == Result::kNotFound) {
                            init_automataState(_fs);
                            auto key = query_key{_ac.get_flow_key_hash(), _ac.get_flow_key_hash()};
                            return _f._mc.query(Operation::kSet, mica_key(key),
                                    mica_value(_fs)).then([this](mica_response response){
                                return make_ready_future<>();
                            });
                        }
                        else {
                            _fs = response.get_value<ips_flow_state>();
                            return make_ready_future<>();
                        }
                    });*/
                    IPS::init_automataState(_fs);
                }
            }
        }

        void per_flow_enqueue(rte_packet pkt,process_type type) {
            //std::cout<<"pkt_num:"<<_f._pkt_counter<<std::endl;
            update_state(_f._batch.current_idx);
                                   //update the flow state when receive the first pkt of this flow in this batch.

            if(likely(type==process_type::hybernate)){
                if(packets[_f._batch.current_idx].empty()){
                    _f._batch._flows[_f._batch.current_idx].push_back(this);
                }

                _f._pkt_counter++;
                packets[_f._batch.current_idx].push_back(std::move(pkt));

                /*if(_f._pkt_counter>=_batch_size){
                     _f._pkt_counter=0;
                     _f._batch.current_idx=!_f._batch.current_idx;
                     _f._batch.schedule_task(!_f._batch.current_idx);
                 }*/
            }else if(type == process_type::cpu_only){
                process_pkt(&pkt,&_fs);
                _f.send_pkt(std::move(pkt));
            }

        }

    };


    enum class ip_protocol_num : uint8_t {
        icmp = 1, tcp = 6, udp = 17, unused = 255
    };

    enum class eth_protocol_num : uint16_t {
        ipv4 = 0x0800, arp = 0x0806, ipv6 = 0x86dd
    };

    const uint8_t eth_hdr_len = 14;
    const uint8_t tcp_hdr_len_min = 20;
    const uint8_t iphdr_len_min = 20;
    const uint8_t ipv6_hdr_len_min = 40;
    const uint16_t ip_packet_len_max = 65535;

    void time_trigger_schedule(){
        if (_pkt_counter==0) return;
        _pkt_counter=0;
        _batch.current_idx=!_batch.current_idx;
        _batch.schedule_task(!_batch.current_idx);

    }

    void dispath_flow(rte_packet pkt){

        process_type type = process_type::hybernate;
        if(_lcore_id>=MAX_GPU_THREAD ){
            //printf("lore_id >2 :%d",_lcore_id);
            type = process_type::cpu_only;
        }
        auto eth_h = pkt.get_header<ether_hdr>(0);
        if(!eth_h) {
            drop_pkt(std::move(pkt));
        }

        if(ntohs(eth_h->ether_type) == static_cast<uint16_t>(eth_protocol_num::ipv4)) {
            auto ip_h = pkt.get_header<iphdr>(sizeof(ether_hdr));
            if(!ip_h) {
                drop_pkt(std::move(pkt));
            }

            // The following code blocks checks and regulates
            // incoming IP packets.
            unsigned ip_len = ntohs(ip_h->tot_len);
            unsigned iphdr_len = ip_h->ihl * 4;
            unsigned pkt_len = pkt.len() - sizeof(ether_hdr);
            auto frag= ntohs(ip_h->frag_off);
            auto offset = frag<<3;
            auto mf = frag & (1 << 13);
            if (pkt_len > ip_len) {
                pkt.trim_back(pkt_len - ip_len);
            } else if (pkt_len < ip_len) {
                drop_pkt(std::move(pkt));
            }
            if (mf == true || offset != 0) {
                drop_pkt(std::move(pkt));
            }

            if(ip_h->protocol == static_cast<uint8_t>(ip_protocol_num::udp)) {
                auto udp_h =
                        pkt.get_header<udp_hdr>(
                                sizeof(ether_hdr)+iphdr_len);
                if(!udp_h) {
                    drop_pkt(std::move(pkt));
                }

                flow_key fk{ntohl(ip_h->daddr),
                                        ntohl(ip_h->saddr),
                                        ntohs(udp_h->dst_port),
                                        ntohs(udp_h->src_port)};
                auto afi = _flow_table.find(fk);
                if(afi == _flow_table.end()) {

                    auto impl_lw_ptr =  new flow_operator(*this);
                    auto succeed = _flow_table.insert({fk, impl_lw_ptr}).second;
                    assert(succeed);
                    impl_lw_ptr->per_flow_enqueue(std::move(pkt),type);
                }
                else {
                    afi->second->per_flow_enqueue(std::move(pkt),type);
                }
                if(_pkt_counter>=_batch_size){
                     _pkt_counter=0;
                     _batch.current_idx=!_batch.current_idx;
                     _batch.schedule_task(!_batch.current_idx);
                 }

                return;
            }
            else if(ip_h->protocol == static_cast<uint8_t>(ip_protocol_num::tcp)) {
                auto tcp_h =
                        pkt.get_header<tcp_hdr>(
                                sizeof(ether_hdr)+iphdr_len);
                if(!tcp_h) {
                    drop_pkt(std::move(pkt));
                }

                auto data_offset = tcp_h->data_off >> 4;
                if (size_t(data_offset * 4) < 20) {
                    drop_pkt(std::move(pkt));
                }

                flow_key fk{ntohl(ip_h->daddr),
                                        ntohl(ip_h->saddr),
                                        ntohs(tcp_h->dst_port),
                                        ntohs(tcp_h->src_port)};
                auto afi = _flow_table.find(fk);
                if(afi == _flow_table.end()) {

                    auto impl_lw_ptr =  new flow_operator(*this);
                    auto succeed = _flow_table.insert({fk, impl_lw_ptr}).second;
                    assert(succeed);
                    impl_lw_ptr->per_flow_enqueue(std::move(pkt),type);

                }
                else {
                    afi->second->per_flow_enqueue(std::move(pkt),type);
                }
                if(_pkt_counter>=_batch_size){
                     _pkt_counter=0;
                     _batch.current_idx=!_batch.current_idx;
                     _batch.schedule_task(!_batch.current_idx);
                 }

                return;
            }
            else{
                drop_pkt(std::move(pkt));
            }
        }
        else{
            drop_pkt(std::move(pkt));
        }

    }

    void send_pkt(rte_packet pkt){
        _send_buffer.push_back(pkt.get_packet());
        if(_send_buffer.size()==MAX_PKT_BURST){

            rte_mbuf** buf_addr=&_send_buffer[0];

            send_brust(_port_id,_queue_id,_lcore_id, buf_addr);

            _send_buffer.clear();
        }
    }

    void drop_pkt(rte_packet pkt){
        rte_pktmbuf_free(pkt.get_packet());
    }


    static bool CompLess(const flow_operator* lhs, const flow_operator* rhs) {
        return lhs->packets[!lhs->_f._batch.current_idx].size() < rhs->packets[!lhs->_f._batch.current_idx].size();
    }

    class batch {

        struct profile_elements{

            uint64_t gpu_flow_num;
            uint64_t max_pkt_num_gpu_flow;
            uint64_t cpu_total_pkt_num;
            uint64_t gpu_total_pkt_num;
            double gpu_copy_time;
            double gpu_process_time;
            double cpu_process_time;
        };

        struct parameters{
            int multi_processor_num;
            int thread_per_block;
            double cpu_process_rate;
            double gpu_process_rate;
            double gpu_copy_rate;
        };

    public:
        std::vector<flow_operator*> _flows[2];
        PKT* gpu_pkts[2];
        nf_flow_state* gpu_states[2];
        PKT* dev_gpu_pkts;
        nf_flow_state* dev_gpu_states;
        uint64_t current_idx;
        cudaStream_t stream;
        cuda_mem_allocator _cuda_mem_allocator;
        int pre_ngpu_pkts;
        int pre_ngpu_states;
        int pre_max_pkt_num_per_flow;
        int pre_partition;
        unsigned lcore_id;


        bool _profileing;
        profile_elements _profile_elements;
        parameters _parameters;

        batch():dev_gpu_pkts(nullptr),dev_gpu_states(nullptr),current_idx(0),pre_ngpu_pkts(0),pre_ngpu_states(0),pre_max_pkt_num_per_flow(0),pre_partition(0),_profileing(true){
            create_stream(&stream);
            lcore_id = rte_lcore_id();
        }

        ~batch(){
            destory_stream(stream);
        }

        void compute_parameter(){

            cudaDeviceProp deviceProp;
            cudaGetDeviceProperties(&deviceProp, 0);
            _parameters.multi_processor_num = deviceProp.multiProcessorCount;
            _parameters.thread_per_block = THREADPERBLOCK;
            _parameters.cpu_process_rate = _profile_elements.cpu_process_time/_profile_elements.cpu_total_pkt_num;
            _parameters.gpu_copy_rate = _profile_elements.gpu_copy_time/_profile_elements.gpu_total_pkt_num;
            int stage = (_profile_elements.gpu_flow_num/_parameters.multi_processor_num/_parameters.thread_per_block)+1;
            _parameters.gpu_process_rate = _profile_elements.gpu_process_time/(_profile_elements.max_pkt_num_gpu_flow*stage);


            _profileing = false;

        }

        void adjust_cpu_process_rate(){
            _parameters.cpu_process_rate = _profile_elements.cpu_process_time/_profile_elements.cpu_total_pkt_num;
        }

        double compute_gpu_time(uint64_t flow_num, uint64_t pkt_num, uint64_t max_pkt_per_flow){
            int stage = (flow_num/_parameters.multi_processor_num/_parameters.thread_per_block)+1;

            double process_time = stage*max_pkt_per_flow*_parameters.gpu_process_rate;
            double copy_time = pkt_num *_parameters.gpu_copy_rate;
            return process_time+copy_time;
        }

        double compute_cpu_time(uint64_t pkt_num){
            return _parameters.cpu_process_rate*pkt_num;
        }

        void schedule_task(uint64_t index){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU
            schedule_timer_tsc = 0;
            if(print_simple_time){
                simple_stoped[lcore_id] = steady_clock_type::now();
                auto simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                printf("Simple Enqueuing time: %f\n", static_cast<double>(simple_elapsed.count() / 1.0));
                simple_started[lcore_id] = steady_clock_type::now();
            }



            stoped[lcore_id] = steady_clock_type::now();
            auto elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time) printf("Enqueuing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();


            int partition=0;
            if(_batch_size!=1){
                sort(_flows[index].begin(),_flows[index].end(),CompLess);
                partition=get_partition(index);
                //partition=_flows[index].size();
                if(print_time)std::cout<<"Total flow_num:"<<_flows[index].size()<<std::endl;
                if(print_time)printf("partition: %d\n",partition);
            }
            assert(partition!=-1);

            stoped[lcore_id] = steady_clock_type::now();
            elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time)printf("Scheduling time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();

            if(partition>0) {

                int max_pkt_num_per_flow=_flows[index][partition-1]->packets[index].size();
                int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(PKT);
                if(print_time)std::cout<<"ngpu_pkts:"<<ngpu_pkts/sizeof(PKT)<<std::endl;
                int ngpu_states = partition * sizeof(nf_flow_state);
                gpu_pkts[index] = (PKT*)malloc(ngpu_pkts);
                gpu_states[index] = (nf_flow_state*)malloc(ngpu_states);
            //    gpu_malloc_host((void**)&gpu_pkts[index],ngpu_pkts);
            //  gpu_malloc_host((void**)&gpu_states[index],ngpu_states);

                assert(gpu_pkts[index]);
                assert(gpu_states[index]);

                // Clear and map gpu_pkts and gpu_states
                memset(gpu_pkts[index], 0, ngpu_pkts);
                memset(gpu_states[index], 0, ngpu_states);
                //printf("gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);
                gpu_mem_map(gpu_pkts[index], ngpu_pkts);
                gpu_mem_map(gpu_states[index], ngpu_states);
                started[lcore_id] = steady_clock_type::now();
//#pragma omp parallel for

                for(int i = 0; i < partition; i++){

                    for(int j = 0; j < (int)_flows[index][i]->packets[index].size(); j++){

                        rte_memcpy(gpu_pkts[index][i*max_pkt_num_per_flow+j].pkt,reinterpret_cast<char*>(_flows[index][i]->packets[index][j].get_header<ether_hdr>(0)),_flows[index][i]->packets[index][j].len());
                    }
                }

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("batch pkt time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                //sync last batch's result and copy them back to host
                if(_flows[!index].empty()==false){
                    started[lcore_id] = steady_clock_type::now();
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d, Sync time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();
//#pragma omp parallel for
                  //  {
                        for(int i = 0; i < pre_partition; i++){
                            //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                            //assert(gpu_states[!index][i]._dfa_id<200);
                            rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(nf_flow_state));

                         //   for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                         //       rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                         //   }
                        }
                  //  }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,Copyback time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    // Unmap gpu_pkts and gpu_states
                    gpu_mem_unmap(gpu_pkts[!index]);
                    gpu_mem_unmap(gpu_states[!index]);
                  //  gpu_free_host(gpu_pkts[!index]);
                  //  gpu_free_host(gpu_states[!index]);
                  //  gpu_pkts[!index]=nullptr;
                  //  gpu_states[!index]=nullptr;

                    // Forward GPU packets[current_idx]
                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }

                    if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }
                    _flows[!index].clear();
                }

                started[lcore_id] = steady_clock_type::now();
                //batch the current state
//#pragma omp parallel for
                for(int i = 0; i < partition; i++){
                    //gpu_states[i] = reinterpret_cast<char*>(&(_flows[index][i]->_fs));
                    rte_memcpy(&gpu_states[index][i],&(_flows[index][i]->_fs),sizeof(nf_flow_state));
                    //assert(gpu_states[index][i]._dfa_id<200);
                }

                pre_ngpu_pkts=ngpu_pkts;
                pre_ngpu_states=ngpu_states;
                pre_max_pkt_num_per_flow=max_pkt_num_per_flow;
                pre_partition=partition;

                dev_gpu_pkts=_cuda_mem_allocator.gpu_pkt_batch_alloc(ngpu_pkts/sizeof(PKT));
                dev_gpu_states=_cuda_mem_allocator.gpu_state_batch_alloc(ngpu_states/sizeof(nf_flow_state));
                assert(dev_gpu_pkts!=nullptr&&dev_gpu_states!=nullptr);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore: %d,Batching state time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                if(gpu_time||_profileing){
                    gpu_sync(stream);
                    started[lcore_id] = steady_clock_type::now();
                }

                gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);

                if(gpu_time||_profileing){
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    printf("lcore %d copy pkt to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();
                    _profile_elements.gpu_copy_time = static_cast<double>(elapsed.count() / 1.0);
                }


                //gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                //gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);
                //std::thread t1(batch_copy2device,dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream,dev_gpu_states,gpu_states[index],ngpu_states);
                //t1.detach();
                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore %d Memcpy to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));


                //printf("----gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);
                /////////////////////////////////////////////
                // Launch kernel
                if(gpu_time||_profileing){
                	gpu_sync(stream);
                started[lcore_id] = steady_clock_type::now();
                }
                gpu_launch((char *)dev_gpu_pkts, (char *)dev_gpu_states, 
                    (char *)(_flows[0][index]->_f._nf->info_for_gpu), max_pkt_num_per_flow, partition,stream);

                if(print_time)  printf("lcore_id: %d gpu launced just now\n", lcore_id);
                if(gpu_time||_profileing){
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    printf("lcore %d sync time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();
                    _profile_elements.gpu_process_time = static_cast<double>(elapsed.count() / 1.0);
                }

                started[lcore_id] = steady_clock_type::now();

                gpu_memcpy_async_d2h(gpu_pkts[index],dev_gpu_pkts,pre_ngpu_pkts,stream);
                gpu_memcpy_async_d2h(gpu_states[index],dev_gpu_states,pre_ngpu_states,stream);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)  printf("lcore_id: %d Memcpy device to host time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();



            } else {
                if(_flows[!index].empty()==false){
                    started[lcore_id] = steady_clock_type::now();
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,Sync time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    for(int i = 0; i < pre_partition; i++){
                        //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                        //assert(gpu_states[!index][i]._dfa_id<200);
                        rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(nf_flow_state));

                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                        }
                    }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,Copyback time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    // Unmap gpu_pkts and gpu_states
                    gpu_mem_unmap(gpu_pkts[!index]);
                    gpu_mem_unmap(gpu_states[!index]);
               //     gpu_free_host(gpu_pkts[!index]);
               //     gpu_free_host(gpu_states[!index]);
              //      gpu_pkts[!index]=nullptr;
              //      gpu_states[!index]=nullptr;

                    // Forward GPU packets[current_idx]
                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }

                    if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }
                    _flows[!index].clear();
                }
            }

            started[lcore_id] = steady_clock_type::now();

            for(unsigned int i = partition; i < _flows[index].size(); i++){
                _flows[index][i]->process_pkts(index);
            }
            if(partition==0){
                _flows[index].clear();
            }

            stoped[lcore_id] = steady_clock_type::now();
            elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time)printf("lcore: %d,CPU processing time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();
            if(_profileing){
                _profile_elements.cpu_process_time = static_cast<double>(elapsed.count() / 1.0);
                compute_parameter();
            }
            _profile_elements.cpu_process_time = static_cast<double>(elapsed.count() / 1.0);
            adjust_cpu_process_rate();

            if(print_simple_time){
                simple_stoped[lcore_id] = steady_clock_type::now();
                auto simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                printf("Task schedule time: %f\n", static_cast<double>(simple_elapsed.count() / 1.0));
                simple_started[lcore_id] = steady_clock_type::now();

            }



        }

        uint64_t get_partition(uint64_t index){
            float processing_time=0;
            float min_processing_time=10000000000;
            float cpu_processing_num=0;
            float pre_cpu_processing_num=0;
            //return _flows[index].size();
            if(_profileing){

                _profile_elements.gpu_flow_num = _flows[index].size()/2;
                _profile_elements.max_pkt_num_gpu_flow = _flows[index][_flows[index].size()/2-1]->packets[index].size();

                for(unsigned int j=_profile_elements.gpu_flow_num;j<_flows[index].size();j++){
                        _profile_elements.cpu_total_pkt_num+=_flows[index][j]->packets[index].size();
                    }
                _profile_elements.gpu_total_pkt_num = _batch_size - _profile_elements.cpu_total_pkt_num ;
                return _profile_elements.gpu_flow_num;
            }

            float cpu_time=0;
            float _gpu_time=0;
            int cpu_pkt_num=0;
            int _gpu_pkt_num=0;
            int _gpu_max_num=0;
            for(int i=_flows[index].size();i>=0;i--){

                if(i>0)
                    _gpu_max_num=_flows[index][i-1]->packets[index].size();
                if(i ==_flows[index].size() ){
                    cpu_pkt_num = 0;
                }else{
                    cpu_pkt_num+=_flows[index][i]->packets[index].size();
                }
                _gpu_pkt_num = _batch_size - cpu_pkt_num;
                _gpu_time = compute_gpu_time(i,_gpu_pkt_num,_gpu_max_num);
                cpu_time = compute_cpu_time(cpu_pkt_num);
                processing_time=std::max(_gpu_time,cpu_time);
                pre_cpu_processing_num=cpu_processing_num;
                cpu_processing_num=cpu_pkt_num;
                if(processing_time>=min_processing_time){
                    if(print_time)std::cout<<"cpu_pkts_processed: "<<pre_cpu_processing_num<<std::endl;
                    if(print_time)std::cout<<"caculated cpu processed time: "<<cpu_time<<std::endl;
                    if(print_time)std::cout<<"caculated gpu processed time: "<<_gpu_time<<std::endl;
                    _profile_elements.cpu_total_pkt_num = cpu_pkt_num;
                    if(i==0){
                        if(print_time||gpu_time)    std::cout<<"GPU_max_pkt: "<<0<<std::endl;
                        return 0;
                    }else{
                        if(print_time||gpu_time)   std::cout<<"GPU_max_pkt: "<<_flows[index][i]->packets[index].size()<<std::endl;
                        return i+1;
                    }
                    //std::cout<<"    min_processing_time:"<<*result<<std::endl;
                } else {
                    min_processing_time=processing_time;
                }
            }
            return 0;
        }
    };

    struct flow_key {
        uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
        flow_key(uint32_t saddr,uint32_t daddr, uint16_t sport, uint16_t dport) :
            saddr(saddr),daddr(daddr),sport(sport),dport(dport) {
        }
    };

    struct HashFunc {
        std::size_t operator()(const flow_key &key) const
        {
          using std::size_t;
          using std::hash;

          return ((hash<int>()(key.saddr)
              ^ (hash<int>()(key.daddr) << 1)) >> 1)
              ^ (hash<int>()(key.sport) << 1)
              ^(hash<int>()(key.dport) << 1);
        }
    };

    struct EqualKey {
        bool operator () (const flow_key &lhs, const flow_key &rhs) const
        {
          return lhs.saddr  == rhs.saddr
              && lhs.daddr == rhs.daddr
              && lhs.sport  == rhs.sport
              && lhs.dport == rhs.dport;
        }
    };


public:
    static NF* _nf;
    batch _batch;
    uint64_t _pkt_counter;
    uint16_t _port_id;
    uint16_t _queue_id;
    uint16_t _lcore_id;
    std::vector<rte_mbuf*> _send_buffer;
    std::unordered_map<flow_key,flow_operator*,HashFunc,EqualKey> _flow_table;
};

#endif // FORWARDER_HH
