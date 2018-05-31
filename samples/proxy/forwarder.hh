#ifndef FORWARDER_HH
#define FORWARDER_HH

#include "nf.hh"
#include <omp.h>
#include <future>
#include "../include/gpu_interface.hh"

extern uint64_t _batch_size;
extern uint64_t print_time;
extern uint64_t gpu_time;
extern uint64_t print_simple_time;
extern uint64_t schedule_timer_tsc[10];
extern uint64_t schedule;
extern uint64_t dynamic_adjust;



#define COMPUTE_RATIO   100
#define MAX_PKT_SIZE    64
#define MAX_FLOW_NUM    40000
#define MAX_GPU_THREAD  10
#define THREADPERBLOCK  256
#define MAX_THRESHOLD  40000*300

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
    char* dev_pkt_batch_ptr;
    nf_flow_state* dev_state_batch_ptr;

    cuda_mem_allocator(){
        gpu_malloc((void**)(&dev_pkt_batch_ptr),sizeof(char)*MAX_THRESHOLD);
        gpu_malloc((void**)(&dev_state_batch_ptr),sizeof(nf_flow_state)*MAX_FLOW_NUM);
    }

    ~cuda_mem_allocator(){}

    char* gpu_pkt_batch_alloc(int size) {
        if(size>MAX_THRESHOLD) {
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
    forwarder(uint16_t port_id, uint16_t queue_id, uint16_t _lcore_id) :_total_byte(0),
        _port_id(port_id),_queue_id(queue_id),_lcore_id(_lcore_id),_message_counter(0){
        for(int i = 0;i<5000;i++){
            _free_flow_operators.push_back(new flow_operator(this, false,nullptr));
        }

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
        forwarder* _f;
        bool _is_from_client;
        struct bufferevent *_dst;

        // nf_flow_state _fs;
        nf_flow_state _fs;

        std::vector<message> packets[2];
        bool _initialized;
        size_t _current_byte[2];



        flow_operator(forwarder* f,bool is_from_client,struct bufferevent *dst):
            _f(f)
            ,_is_from_client(is_from_client)
            ,_dst(dst)
            ,_initialized(false)
            {

            _nf->init_automataState(_fs);
            _current_byte[0]=0;
            _current_byte[1]=0;
        }
        flow_operator(const flow_operator& other) = delete;
        flow_operator(flow_operator&& other) noexcept
            :_f(other._f),_fs(other._fs),_dst(other._dst),_is_from_client(other._is_from_client),_initialized(other._initialized){
            packets[0] = std::move(other.packets[0]);
            packets[1] = std::move(other.packets[1]);
            _current_byte[0]=other._current_byte[0];
            _current_byte[1]=other._current_byte[1];

            _nf->init_automataState(_fs);
        }
        ~flow_operator() {}


        void forward_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){
                _f->send_pkt(std::move(packets[index][i]),_dst);
            }
            packets[index].clear();
            _current_byte[index]=0;
            assert(packets[index].size()==0);
        }

        void process_pkts(uint64_t index){
            for(unsigned int i=0;i<packets[index].size();i++){
                process_pkt(&packets[index][i],&_fs);
            }
            forward_pkts(index);
        }

        void process_pkt(message* pkt, nf_flow_state* fs){
            _nf->nf_logic(pkt->msg, fs);
            //printf("process messages\n");
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
                    _nf->init_automataState(_fs);
                }
            }
        }

        void per_flow_enqueue(message pkt,process_type type) {
            //std::cout<<"pkt_num:"<<_f._message_counter<<std::endl;
            update_state(_f->_batch.current_idx);
                                   //update the flow state when receive the first pkt of this flow in this batch.

            if(likely(type==process_type::hybernate)){
                if(packets[_f->_batch.current_idx].empty()){
                    _f->_batch._flows[_f->_batch.current_idx].push_back(this);
                }

                _f->_total_byte+=pkt.len();
                _f->_message_counter++;
                _current_byte[_f->_batch.current_idx]+=pkt.len();
                packets[_f->_batch.current_idx].push_back(std::move(pkt));


                /*if(_f._total_byte>=_batch_size){
                     _f._total_byte=0;
                     _f._batch.current_idx=!_f._batch.current_idx;
                     _f._batch.schedule_task(!_f._batch.current_idx);
                 }*/
            }else if(type == process_type::cpu_only){
                process_pkt(&pkt,&_fs);
                _f->send_pkt(std::move(pkt),_dst);
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
        if ((_total_byte==0&&_batch._flows[0].size()==0&&_batch._flows[1].size()==0)) return;

        _batch.current_idx=!_batch.current_idx;
        printf("lcore_id: %d, trigger\n",_lcore_id);
        _batch.schedule_task(!_batch.current_idx,_total_byte);
        _total_byte=0;
        _message_counter=0;


    }

    void create_flow_operator(bool is_from_client, bufferevent* src, bufferevent* dst){
        if(_free_flow_operators.size()==0){
            _free_flow_operators.push_back(new flow_operator(this, false,nullptr));
        }
        auto afi = _flow_table.find(src);
        assert(afi==_flow_table.end());
        auto impl_lw_ptr =  _free_flow_operators.back();
        impl_lw_ptr->_is_from_client = is_from_client;
        impl_lw_ptr->_dst = dst;
        _free_flow_operators.pop_back();//new flow_operator(this,is_from_client,dst);
        auto succeed = _flow_table.insert({src, impl_lw_ptr}).second;
        assert(succeed);
    }
    void free_flow_operator(bufferevent* src){
        auto afi = _flow_table.find(src);
        assert(afi!=_flow_table.end());
        _free_flow_operators.push_back(afi->second);
        _flow_table.erase(src);
    }

    void dispath_flow(message pkt, bool is_from_client, bufferevent* src, bufferevent* dst){

        process_type type = process_type::hybernate;
        if(_lcore_id>=MAX_GPU_THREAD ){
            //printf("lore_id >2 :%d",_lcore_id);
            type = process_type::cpu_only;
        }

        if(_total_byte==0){
            lt_started[_batch.current_idx] = steady_clock_type::now();
         }

            // The following code blocks checks and regulates
            // incoming IP packets.


        auto afi = _flow_table.find(src);
        if(afi == _flow_table.end()) {

          //  auto impl_lw_ptr =  new flow_operator(*this,is_from_client,dst);
          //  auto succeed = _flow_table.insert({src, impl_lw_ptr}).second;
          //  assert(succeed);
          //  impl_lw_ptr->per_flow_enqueue(std::move(pkt),type);
            printf("already removed!!\n");
            exit(-1);

        }
        else {
            afi->second->per_flow_enqueue(std::move(pkt),type);

        }
        //if(_total_byte>=_batch_size){
        if(_message_counter>=_batch_size){


             _batch.current_idx=!_batch.current_idx;
             _batch.schedule_task(!_batch.current_idx,_total_byte);
             _total_byte=0;
             _message_counter=0;

         }

        }



    void send_pkt(message pkt, bufferevent* dst){

        //printf("msg len:%d\n",pkt.length);
        //printf("send len:%d\n",*((size_t*)(pkt.msg)));
        assert(dst);
       // auto f = _flow_table.find(dst);
       // if(f!=_flow_table.end()){

            bufferevent_write(dst,pkt.msg+sizeof(size_t),*((size_t*)(pkt.msg)));

       // }
        //printf("send_buffer: %x\n",dst);



        free(pkt.msg);
        pkt.msg = nullptr;


    }

    void drop_pkt(message pkt){
        //rte_pktmbuf_free(pkt.get_packet());
    }


    static bool CompLess(const flow_operator* lhs, const flow_operator* rhs) {
        return lhs->_current_byte[!lhs->_f->_batch.current_idx] < rhs->_current_byte[!lhs->_f->_batch.current_idx];
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
            double cpu_enqueue_time;
        };

        struct parameters{
            int multi_processor_num;
            int thread_per_block;
            double cpu_process_rate;
            double cpu_enqueue_rate;
            double gpu_process_rate;
            double gpu_copy_rate;
        };

    public:
        std::vector<flow_operator*> _flows[2];
        char* gpu_pkts[2];
        nf_flow_state* gpu_states[2];
        char* dev_gpu_pkts;
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
        int _profile_num;
        bool _period_profile;
        int _period_profile_num = 0;
        profile_elements _profile_elements;
        parameters _parameters;
        bool _timer_reactivate;

        batch():dev_gpu_pkts(nullptr),dev_gpu_states(nullptr),current_idx(0),pre_ngpu_pkts(0),pre_ngpu_states(0),pre_max_pkt_num_per_flow(0),pre_partition(0),_profileing(true),_profile_num(0),_period_profile(false),_period_profile_num(0),_timer_reactivate(true){
            create_stream(&stream);
            lcore_id = 0;
            gpu_malloc_host((void**)(&gpu_pkts[0]),sizeof(char)*MAX_THRESHOLD);
            gpu_malloc_host((void**)(&gpu_pkts[1]),sizeof(char)*MAX_THRESHOLD);
            gpu_malloc_host((void**)(&gpu_states[0]),sizeof(nf_flow_state)*MAX_FLOW_NUM);
            gpu_malloc_host((void**)(&gpu_states[1]),sizeof(nf_flow_state)*MAX_FLOW_NUM);

            memset(gpu_pkts[0], 0, sizeof(char)*MAX_THRESHOLD);
            memset(gpu_pkts[1], 0, sizeof(char)*MAX_THRESHOLD);
            memset(gpu_states[0], 0, sizeof(nf_flow_state)*MAX_FLOW_NUM);
            memset(gpu_states[1], 0, sizeof(nf_flow_state)*MAX_FLOW_NUM);

        }

        ~batch(){
            destory_stream(stream);
        }
        void reset_batch(uint64_t index){
            memset(gpu_pkts[index], 0, sizeof(char)*MAX_THRESHOLD);
            memset(gpu_states[index], 0, sizeof(nf_flow_state)*MAX_FLOW_NUM);
        }

        void compute_parameter(){

            cudaDeviceProp deviceProp;
            cudaGetDeviceProperties(&deviceProp, 0);
            _parameters.multi_processor_num = deviceProp.multiProcessorCount;
            _parameters.thread_per_block = THREADPERBLOCK;
            if(_profile_elements.cpu_total_pkt_num!=0) _parameters.cpu_process_rate = _profile_elements.cpu_process_time/_profile_elements.cpu_total_pkt_num;
            if(_profile_elements.gpu_total_pkt_num!=0) _parameters.gpu_copy_rate = _profile_elements.gpu_copy_time/_profile_elements.gpu_total_pkt_num;
            int stage = (_profile_elements.gpu_flow_num/_parameters.multi_processor_num/_parameters.thread_per_block)+1;
            _parameters.gpu_process_rate = _profile_elements.gpu_process_time/(_profile_elements.max_pkt_num_gpu_flow*stage);
            _parameters.cpu_enqueue_rate = _profile_elements.cpu_enqueue_time/_batch_size;

        }

        void adjust_cpu_process_rate(){
            _parameters.cpu_process_rate = _profile_elements.cpu_process_time/_profile_elements.cpu_total_pkt_num;
        }

        void adjust_enqueue_rate(){
            _parameters.cpu_enqueue_rate = _profile_elements.cpu_enqueue_time/_batch_size;
        }

        double compute_gpu_time(uint64_t flow_num, uint64_t pkt_num, uint64_t max_pkt_per_flow){
            int stage = (flow_num/_parameters.multi_processor_num/_parameters.thread_per_block)+1;

            double process_time = stage*max_pkt_per_flow*_parameters.gpu_process_rate;
            double copy_time = pkt_num *_parameters.gpu_copy_rate;



            return process_time+copy_time;
        }



        double compute_cpu_time(uint64_t pkt_num){

            return _parameters.cpu_process_rate*pkt_num+_batch_size*_parameters.cpu_enqueue_rate;


        }


        bool need_periodical_profile(){
            if(_profileing||_period_profile||_batch_size==1){
                return false;
            }
            _period_profile_num ++;
            if(_period_profile_num==500){
                _period_profile_num = 0;
                printf("periodical profile\n");
                return true;


            }
            return false;
        }

        void schedule_task(uint64_t index, uint64_t total_byte){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU
        	 //schedule_timer_tsc[lcore_id] = 0;
            _timer_reactivate=true;
            if(unlikely(_profile_num<5)){
                _profile_num++;
                printf("lcore_id: %d, Profiling......\n",lcore_id);
            }else{
                if(unlikely(_profileing&&lcore_id ==0&& dynamic_adjust)){
                    _batch_size = 1024;

                }
                _profileing = false;

            }
            _period_profile = need_periodical_profile();
            simple_stoped[lcore_id] = steady_clock_type::now();
            auto simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];

            if(_profileing||_period_profile) _profile_elements.cpu_enqueue_time = static_cast<double>(simple_elapsed.count() / 1.0);
            //adjust_enqueue_rate();
            if(print_simple_time) printf("locre: %d,Simple Enqueuing time: %f\n", lcore_id,static_cast<double>(simple_elapsed.count() / 1.0));
            simple_started[lcore_id] = steady_clock_type::now();




            stoped[lcore_id] = steady_clock_type::now();
            auto elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time) printf("lcore %d,Enqueuing time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();


            int partition=0;
            if(_batch_size!=1){
                sort(_flows[index].begin(),_flows[index].end(),CompLess);
                partition=get_partition(index,total_byte);
                if(print_time)printf("lcore %d,partition: %d\n",lcore_id, partition);
                //partition=_flows[index].size();
                if(print_time)std::cout<<"lcore_id: "<<lcore_id<<"Total flow_num:"<<_flows[index].size()<<std::endl;
                if(print_time)printf("lcore %d,partition: %d\n",lcore_id, partition);
            }
            assert(partition!=-1);

            stoped[lcore_id] = steady_clock_type::now();
            elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time)printf("lcore %d ,Scheduling time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();


            simple_stoped[lcore_id] = steady_clock_type::now();
            simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
            if(print_simple_time)    printf("lcore: %d, simple schedule time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

            if(partition>0) {

                int max_pkt_num_per_flow=_flows[index][partition-1]->_current_byte[index];
                int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(char);
                //ngpu_pkts = ((ngpu_pkts+7)/8)*8;
                if(print_time)std::cout<<"ngpu_pkts:"<<ngpu_pkts/sizeof(char)<<std::endl;
                int ngpu_states = partition * sizeof(nf_flow_state);
                //gpu_pkts[index] = (PKT*)malloc(ngpu_pkts);
                //gpu_states[index] = (nf_flow_state*)malloc(ngpu_states);
            //    gpu_malloc_host((void**)&gpu_pkts[index],ngpu_pkts);
            //  gpu_malloc_host((void**)&gpu_states[index],ngpu_states);

                assert(gpu_pkts[index]);
                assert(gpu_states[index]);

                // Clear and map gpu_pkts and gpu_states
                //memset(gpu_pkts[index], 0, ngpu_pkts);
                //memset(gpu_states[index], 0, ngpu_states);
                started[lcore_id] = steady_clock_type::now();

                started[lcore_id] = steady_clock_type::now();
//#pragma omp parallel for

                for(int i = 0; i < partition; i++){
                    size_t len=0;

                    for(int j = 0; j < (int)_flows[index][i]->packets[index].size(); j++){

                        rte_memcpy(gpu_pkts[index]+i*max_pkt_num_per_flow+len,(_flows[index][i]->packets[index][j].msg),_flows[index][i]->packets[index][j].len());
                        len += _flows[index][i]->packets[index][j].len();
                    }
                }

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore %d batch pkt time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                simple_stoped[lcore_id] = steady_clock_type::now();
                simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                if(print_simple_time)    printf("lcore: %d, simple batch pkt time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                //sync last batch's result and copy them back to host
                if(_flows[!index].empty()==false){
                    started[lcore_id] = steady_clock_type::now();
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d, Sync time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();


                    simple_stoped[lcore_id] = steady_clock_type::now();
                    simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                    if(print_simple_time)    printf("lcore: %d, simple sync time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                    for(int i = 0; i < pre_partition; i++){
                        //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                        //assert(gpu_states[!index][i]._dfa_id<200);
                        rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(nf_flow_state));

                        size_t len=0;
                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy((_flows[!index][i]->packets[!index][j].msg),gpu_pkts[!index]+i*(pre_max_pkt_num_per_flow)+len,_flows[!index][i]->packets[!index][j].len());
                            len+=_flows[!index][i]->packets[!index][j].len();
                        }
                    }

                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);

                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,Copyback time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    memset(gpu_pkts[!index],0, pre_ngpu_pkts);
                    memset(gpu_states[!index],0, pre_ngpu_states);


                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,memset time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    simple_stoped[lcore_id] = steady_clock_type::now();
                    simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                    if(print_simple_time)    printf("lcore: %d, simple copyback time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                    // Unmap gpu_pkts and gpu_states
                    //gpu_mem_unmap(gpu_pkts[!index]);
                   // gpu_mem_unmap(gpu_states[!index]);
                  //  gpu_free_host(gpu_pkts[!index]);
                  //  gpu_free_host(gpu_states[!index]);
                  //  gpu_pkts[!index]=nullptr;
                  //  gpu_states[!index]=nullptr;
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,batch unmap time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    // Forward GPU packets[current_idx]

                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }
                    auto time = steady_clock_type::now();
                    auto el = time - _flows[!index][0]->_f->lt_started[!index] ;
                    if(print_simple_time) printf("lcore: %d,batch unmap time: %f\n", lcore_id,static_cast<double>(el.count() / 1.0));

                   /* if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }*/
                    _flows[!index].clear();
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,forward pkts time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    simple_stoped[lcore_id] = steady_clock_type::now();
                    simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                    if(print_simple_time)    printf("lcore: %d, simple forward pkt time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));
                }



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

                dev_gpu_pkts=_cuda_mem_allocator.gpu_pkt_batch_alloc(ngpu_pkts/sizeof(char));
                dev_gpu_states=_cuda_mem_allocator.gpu_state_batch_alloc(ngpu_states/sizeof(nf_flow_state));
                assert(dev_gpu_pkts!=nullptr&&dev_gpu_states!=nullptr);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore: %d,Batching state time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                simple_stoped[lcore_id] = steady_clock_type::now();
                simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                if(print_simple_time)    printf("lcore: %d, simple batching states time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                if(gpu_time||_profileing||_period_profile){
                    gpu_sync(stream);
                    started[lcore_id] = steady_clock_type::now();
                }

                gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);

                if(gpu_time||_profileing||_period_profile){
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(gpu_time)    printf("lcore %d copy pkt to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    simple_stoped[lcore_id] = steady_clock_type::now();
                    simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                    if(print_simple_time)    printf("lcore: %d, simple copy pkt to device time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                    _profile_elements.gpu_copy_time = static_cast<double>(elapsed.count() / 1.0);
                }


                //gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                //gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);
                //std::thread t1(batch_copy2device,dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream,dev_gpu_states,gpu_states[index],ngpu_states);
                //t1.detach();
                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore %d Memcpy to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));

                simple_stoped[lcore_id] = steady_clock_type::now();
                simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                if(print_simple_time)    printf("lcore: %d, simple Memcpy to device time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

                //printf("----gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);
                /////////////////////////////////////////////
                // Launch kernel
                if(gpu_time||_profileing||_period_profile){
                	gpu_sync(stream);
                started[lcore_id] = steady_clock_type::now();
                }
                started[lcore_id] = steady_clock_type::now();
                gpu_launch((char *)dev_gpu_pkts, (char *)dev_gpu_states, 
                    (char *)(_flows[0][index]->_f->_nf->info_for_gpu), max_pkt_num_per_flow, partition,stream);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time) printf("lcore %d gpu launch time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                if(print_time)  printf("lcore_id: %d gpu launced just now\n", lcore_id);
                if(gpu_time||_profileing||_period_profile){
                    gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(gpu_time) printf("lcore %d sync time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
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

                simple_stoped[lcore_id] = steady_clock_type::now();
                simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
                if(print_simple_time)    printf("lcore: %d, simple memcpy device to host time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));


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
                            size_t len=0;
                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy((_flows[!index][i]->packets[!index][j].msg),gpu_pkts[!index]+i*(pre_max_pkt_num_per_flow)+len,_flows[!index][i]->packets[!index][j].len());
                            len+=_flows[!index][i]->packets[!index][j].len();
                        }
                    }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,Copyback time: %f\n",lcore_id, static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();


                    memset(gpu_pkts[!index],0, pre_ngpu_pkts);
                    memset(gpu_states[!index],0, pre_ngpu_states);


                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,memset time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    // Unmap gpu_pkts and gpu_states
                    //gpu_mem_unmap(gpu_pkts[!index]);
                    //gpu_mem_unmap(gpu_states[!index]);
               //     gpu_free_host(gpu_pkts[!index]);
               //     gpu_free_host(gpu_states[!index]);
              //      gpu_pkts[!index]=nullptr;
              //      gpu_states[!index]=nullptr;

                    // Forward GPU packets[current_idx]
                    for(unsigned int i = 0; i < _flows[!index].size(); i++){
                        _flows[!index][i]->forward_pkts(!index);
                    }

                  /*  if(gpu_pkts[!index]){
                        free(gpu_pkts[!index]);
                    }
                    if(gpu_states[!index]){
                        free(gpu_states[!index]);
                    }*/
                    _flows[!index].clear();
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("lcore: %d,forward pkts time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();
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

            simple_stoped[lcore_id] = steady_clock_type::now();
            simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
            if(print_simple_time)    printf("lcore: %d, simple cpu processing time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));

            if(_profileing||_period_profile){
                _profile_elements.cpu_process_time = static_cast<double>(elapsed.count() / 1.0);
                compute_parameter();
            }



            simple_stoped[lcore_id] = steady_clock_type::now();
            simple_elapsed = simple_stoped[lcore_id] - simple_started[lcore_id];
            if(print_simple_time)    printf("lcore: %d, Task schedule time: %f\n",lcore_id, static_cast<double>(simple_elapsed.count() / 1.0));
            simple_started[lcore_id] = steady_clock_type::now();





        }

        uint64_t get_partition(uint64_t index,uint64_t total_byte){
            float processing_time=0;
            float min_processing_time=10000000000;
            float cpu_processing_num=0;
            float pre_cpu_processing_num=0;
            /*for(int i = 0; i<(int)_flows[index].size();i++){
                std::cout<<" "<<_flows[index][i]->packets[index].size()<<" ";
            }
            std::cout<<std::endl;*/
            if(print_time) std::cout<<"max byte: "<<_flows[index][_flows[index].size()-1]->_current_byte[index]<<std::endl;
            if(!schedule) return _flows[index].size();
            if(_profileing||_period_profile){

                _profile_elements.gpu_flow_num = _flows[index].size()/2;
                _profile_elements.cpu_total_pkt_num = 0;
                _profile_elements.max_pkt_num_gpu_flow = _flows[index][_flows[index].size()/2]->_current_byte[index];

                for(int j=_profile_elements.gpu_flow_num;j<(int)_flows[index].size();j++){
                        _profile_elements.cpu_total_pkt_num+=_flows[index][j]->_current_byte[index];
                    }
                _profile_elements.gpu_total_pkt_num = total_byte - _profile_elements.cpu_total_pkt_num ;
                return _profile_elements.gpu_flow_num;
            }

            float cpu_time=0;
            float _gpu_time=0;
            int cpu_pkt_num=0;
            int _gpu_pkt_num=0;
            int _gpu_max_num=0;

            for(int i=_flows[index].size();i>=0;i--){

                if(i>0)
                    _gpu_max_num=_flows[index][i-1]->_current_byte[index];
                if(i ==_flows[index].size() ){
                    cpu_pkt_num = 0;
                }else{
                    cpu_pkt_num+=_flows[index][i]->_current_byte[index];
                }
                _gpu_pkt_num = total_byte - cpu_pkt_num;
                _gpu_time = compute_gpu_time(i,_gpu_pkt_num,_gpu_max_num);
                cpu_time = compute_cpu_time(cpu_pkt_num);
                processing_time=std::max(_gpu_time,cpu_time);
                pre_cpu_processing_num=cpu_processing_num;
                cpu_processing_num=cpu_pkt_num;
                if(processing_time>=min_processing_time){

                    if(print_time)std::cout<<"lcore_id: "<<lcore_id<<"cpu_pkts_processed: "<<pre_cpu_processing_num<<std::endl;
                    if(print_time)std::cout<<"lcore_id: "<<lcore_id<<"caculated cpu processed time: "<<cpu_time<<std::endl;
                    if(print_time)std::cout<<"lcore_id: "<<lcore_id<<"caculated gpu processed time: "<<_gpu_time<<std::endl;
                    if(print_time)printf("lcore: %d,CPU rate: %f\n", lcore_id,_parameters.cpu_process_rate);
                    if(print_time)printf("lcore: %d,GPU rate: %f\n", lcore_id,_parameters.gpu_process_rate);
                    if(print_time)printf("lcore: %d,enqueue rate: %f\n", lcore_id,_parameters.cpu_enqueue_rate);


                    if(i==0){
                        if(print_time||gpu_time)    std::cout<<"lcore_id: "<<lcore_id<<"GPU_max_pkt: "<<0<<std::endl;
                        return 0;
                    }else{
                        if(print_time||gpu_time)   std::cout<<"lcore_id: "<<lcore_id<<"GPU_max_pkt: "<<_flows[index][i]->packets[index].size()<<std::endl;
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
    uint64_t _total_byte;
    uint16_t _port_id;
    uint16_t _queue_id;
    uint16_t _lcore_id;
    std::vector<rte_mbuf*> _send_buffer;
    std::unordered_map<bufferevent*,flow_operator*> _flow_table;
    std::vector<flow_operator*> _free_flow_operators;
    std::chrono::time_point<std::chrono::steady_clock> lt_started[2];
    uint64_t _message_counter;
};

#endif // FORWARDER_HH
