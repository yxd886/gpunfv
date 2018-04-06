/*
 * ips.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef SAMPLES_L2_FORWARD_IPS_HH_
#define SAMPLES_L2_FORWARD_IPS_HH_
#include "../gpu_interface.hh"
#include "../../nf/aho-corasick/fpp.h"
#include "../../nf/aho-corasick/aho.h"
#include <omp.h>
#include <future>


extern uint64_t _batch_size;

extern uint64_t print_time;

#define COMPUTE_RATIO 100

#define MAX_PKT_SIZE 1500

#define MAX_FLOW_NUM 10000

#define DFA_NUM 15



std::chrono::time_point<std::chrono::steady_clock> started[10];
std::chrono::time_point<std::chrono::steady_clock> stoped[10];
using namespace std::chrono;
using steady_clock_type = std::chrono::steady_clock;


struct PKT{

    char pkt[MAX_PKT_SIZE];
};

class IPS{
public:
    IPS(){

        int num_patterns, i;

        int num_threads = 1;
        assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        gpu_malloc((void**)(&gpu_ips), sizeof(IPS));


        struct stat_t *gpu_stats;
        stats =(struct stat_t *)malloc(num_threads * sizeof(struct stat_t));
        assert(stats!=NULL);
        gpu_malloc((void**)(&gpu_stats), num_threads * sizeof(struct stat_t));

        for(i = 0; i < num_threads; i++) {
            stats[i].tput = 0;
        }




        struct aho_pattern *patterns;
        /* Thread structures */
        //pthread_t worker_threads[AHO_MAX_THREADS];


        red_printf("State size = %lu\n", sizeof(struct aho_state));

        /* Initialize the shared DFAs */
        for(i = 0; i < AHO_MAX_DFA; i++) {
            //printf("Initializing DFA %d\n", i);
            printf("i=%d\n",i);
            aho_init(&dfa_arr[i], i);

        }

        red_printf("Adding patterns to DFAs\n");
        patterns = aho_get_patterns(AHO_PATTERN_FILE,
            &num_patterns);

        for(i = 0; i < num_patterns; i++) {
            int dfa_id = patterns[i].dfa_id;
            aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
        }

        red_printf("Building AC failure function\n");
        for(i = 0; i < AHO_MAX_DFA; i++) {
            aho_build_ff(&dfa_arr[i]);
            aho_preprocess_dfa(&dfa_arr[i]);
        }


        gpu_memcpy_async_h2d(gpu_ips, this, sizeof(IPS));

        for(i = 0; i < AHO_MAX_DFA; i++) {

            struct aho_state* gpu_root;
            int offset = (char *)&dfa_arr[i].root - (char *)this;
            char *des_addr = (char *)gpu_ips + offset;
            //printf("i = :%d, max = %d\n",i,AHO_MAX_DFA);
            gpu_malloc((void**)(&gpu_root), AHO_MAX_STATES * sizeof(struct aho_state));

            gpu_memcpy_async_h2d(gpu_root, dfa_arr[i].root, AHO_MAX_STATES * sizeof(struct aho_state));
            gpu_memcpy_async_h2d(des_addr, &gpu_root, sizeof(struct aho_state *));
        }


        gpu_memcpy_async_h2d(gpu_stats, stats, num_threads * sizeof(struct stat_t));

    }
    ~IPS(){

        for(int i = 0; i < AHO_MAX_DFA; i++) {

            //gpu_mem_unmap(dfa_arr[i].root);
            free(dfa_arr[i].root);
        }


        free(stats);
    }
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
    IPS *gpu_ips;

};

struct ips_flow_state{

    uint16_t _state[DFA_NUM];
    int _dfa_id[DFA_NUM];
    bool _alert[DFA_NUM];


};


class cuda_mem_allocator{
public:



    cuda_mem_allocator(){
        gpu_malloc((void**)(&dev_pkt_batch_ptr),sizeof(PKT)*_batch_size*40);
        gpu_malloc((void**)(&dev_state_batch_ptr),sizeof(ips_flow_state)*MAX_FLOW_NUM);



    }
    ~cuda_mem_allocator(){}

    PKT* gpu_pkt_batch_alloc(int size){
        if(size>_batch_size*40){
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

static void batch_copy2device(PKT*dev_gpu_pkts,PKT* host_gpu_pkts,int ngpu_pkts, cudaStream_t stream, ips_flow_state*dev_gpu_states,ips_flow_state*host_gpu_states,int ngpu_states){

    gpu_memcpy_async_h2d(dev_gpu_pkts,host_gpu_pkts,ngpu_pkts,stream);
    gpu_memcpy_async_h2d(dev_gpu_states,host_gpu_states,ngpu_states,stream);

}

class forwarder {

public:
    forwarder(uint16_t port_id, uint16_t queue_id, uint16_t _lcore_id) :_pkt_counter(0),_port_id(port_id),_queue_id(queue_id),_lcore_id(_lcore_id){

    }

    struct mp_list_t {
        int num_match;
        uint16_t ptrn_id[MAX_MATCH];
    };

    struct query_key {
        uint64_t v1;
        uint64_t v2;
    };




    class flow_operator {


    public:
        forwarder& _f;
        ips_flow_state _fs;
        std::vector<rte_packet> packets[2];
        bool _initialized;


        flow_operator(forwarder& f):
            _f(f)
            ,_initialized(false){

            init_automataState(_fs);
        }
        flow_operator(const flow_operator& other) = delete;
        flow_operator(flow_operator&& other) noexcept
            :_f(other._f),_fs(other._fs) ,_initialized(other._initialized){


            packets[0] = std::move(other.packets[0]);
            packets[1] = std::move(other.packets[1]);
            init_automataState(_fs);
        }
        ~flow_operator(){

        }

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
        void process_pkt(rte_packet* pkt, ips_flow_state* fs){


            ips_detect(pkt,fs);

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
                    init_automataState(_fs);

                }
            }

        }

        void run_ips(rte_packet pkt) {


            //std::cout<<"pkt_num:"<<_f._pkt_counter<<std::endl;
            update_state(_f._batch.current_idx);
                                   //update the flow state when receive the first pkt of this flow in this batch.

            if(packets[_f._batch.current_idx].empty()){
                _f._batch._flows[_f._batch.current_idx].push_back(this);
            }

            _f._pkt_counter++;
            packets[_f._batch.current_idx].push_back(std::move(pkt));

            if(_f._pkt_counter>=_batch_size){

                 _f._pkt_counter=0;
                 _f._batch.current_idx=!_f._batch.current_idx;
                 _f._batch.schedule_task(!_f._batch.current_idx);

             }

        }

       void init_automataState(struct ips_flow_state& state){
             for(int i=0;i<DFA_NUM;i++){
                 srand((unsigned)time(NULL));
                 state._state[i]=0;
                 state._alert[i]=false;
                 state._dfa_id[i]=rand()%AHO_MAX_DFA;
             }


             //std::cout<<"init_automataState_dfa_id:"<<state._dfa_id<<std::endl;
         }
       void parse_pkt(rte_packet *rte_pkt, struct ips_flow_state* state,struct aho_pkt*  aho_pkt){

           aho_pkt->content=(uint8_t*)malloc(rte_pkt->len());
           //std::cout<<"    rte_pkt->len():"<<rte_pkt->len()<<std::endl;
           memcpy(aho_pkt->content,reinterpret_cast<uint8_t*>(rte_pkt->get_header(0,sizeof(char))),rte_pkt->len()-1);
           aho_pkt->dfa_id=state->_dfa_id;
           aho_pkt->len=rte_pkt->len();
           //std::cout<<"    aho_pkt->len:"<<rte_pkt->len()<<std::endl;
       }
       bool state_updated(struct ips_flow_state* old_,struct ips_flow_state* new_){
           if(old_->_alert==new_->_alert&&old_->_dfa_id==new_->_dfa_id&&old_->_state==new_->_state){
               return false;
           }
           return true;
       }

       void process_batch(const struct aho_dfa *dfa_arr,
           const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_flow_state* ips_state)
       {
           int I, j;

           for(I = 0; I < BATCH_SIZE; I++) {
               int len = pkts[I].len;

               for(int times=0;times<DFA_NUM;times++){

                   int state = ips_state->_state[times];
                   int dfa_id = pkts[I].dfa_id[times];
                   struct aho_state *st_arr = dfa_arr[dfa_id].root;
                   if(state>=dfa_arr[dfa_id].num_used_states){
                     ips_state->_alert[times]=false;
                     ips_state->_state[times]=0;
                   }

                   for(j = 0; j < len; j++) {

                     int count = st_arr[state].output.count;

                     if(count != 0) {
                         /* This state matches some patterns: copy the pattern IDs
                           *  to the output */
                         int offset = mp_list[I].num_match;
                         memcpy(&mp_list[I].ptrn_id[offset],
                             st_arr[state].out_arr, count * sizeof(uint16_t));
                         mp_list[I].num_match += count;
                         ips_state->_alert[times]=true;
                         ips_state->_state[times]=0;

                     }
                     int inp = pkts[I].content[j];
                     state = st_arr[state].G[inp];
                 }
                 //std::cout<<"      after for loop"<<std::endl;
                 ips_state->_state[times]=state;
               }

           }


       }
       void ids_func(struct aho_ctrl_blk *cb,struct ips_flow_state* state)
       {
           int i, j;



           struct aho_dfa *dfa_arr = cb->dfa_arr;
           struct aho_pkt *pkts = cb->pkts;
           int num_pkts = cb->num_pkts;

           /* Per-batch matched patterns */
           struct mp_list_t mp_list[BATCH_SIZE];
           for(i = 0; i < BATCH_SIZE; i++) {
               mp_list[i].num_match = 0;
           }


           for(i = 0; i < num_pkts; i += BATCH_SIZE) {
               //std::cout<<"    before process_batch"<<std::endl;
               process_batch(dfa_arr, &pkts[i], mp_list,state);
               //std::cout<<"    after process_batch"<<std::endl;

               for(j = 0; j < BATCH_SIZE; j++) {
                   int num_match = mp_list[j].num_match;
                   assert(num_match < MAX_MATCH);


                   mp_list[j].num_match = 0;
               }
           }



       }
       void ips_detect(rte_packet *rte_pkt, struct ips_flow_state* state){


           struct aho_pkt* pkts=(struct aho_pkt* )malloc(sizeof(struct aho_pkt));

           parse_pkt(rte_pkt, state,pkts);

           struct aho_ctrl_blk worker_cb;
           worker_cb.stats = _f.ips->stats;
           worker_cb.tot_threads = 1;
           worker_cb.tid = 0;
           worker_cb.dfa_arr = _f.ips->dfa_arr;
           worker_cb.pkts = pkts;
           worker_cb.num_pkts = 1;
           //std::cout<<"  before ids_func"<<std::endl;
           ids_func(&worker_cb,state);
           //std::cout<<"  after ids_func"<<std::endl;
           free(pkts->content);
           free(pkts);

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



    void dispath_flow(rte_packet pkt){

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
                    impl_lw_ptr->run_ips(std::move(pkt));


                }
                else {
                    afi->second->run_ips(std::move(pkt));
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
                    impl_lw_ptr->run_ips(std::move(pkt));


                }
                else {
                    afi->second->run_ips(std::move(pkt));
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


    static bool CompLess(const flow_operator* lhs, const flow_operator* rhs)
    {
        return lhs->packets[!lhs->_f._batch.current_idx].size() < rhs->packets[!lhs->_f._batch.current_idx].size();
    }
    class batch {
    public:

        std::vector<flow_operator*> _flows[2];
        PKT* gpu_pkts[2];
        ips_flow_state* gpu_states[2];
        PKT* dev_gpu_pkts;
        ips_flow_state* dev_gpu_states;
        uint64_t current_idx;
        cudaStream_t stream;
        cuda_mem_allocator _cuda_mem_allocator;
        int pre_ngpu_pkts;
        int pre_ngpu_states;
        int pre_max_pkt_num_per_flow;
        int pre_partition;
        unsigned lcore_id;


        batch():dev_gpu_pkts(nullptr),dev_gpu_states(nullptr),current_idx(0),pre_ngpu_pkts(0),pre_ngpu_states(0),pre_max_pkt_num_per_flow(0),pre_partition(0){
            create_stream(&stream);
            lcore_id = rte_lcore_id();

        }
        ~batch(){
            destory_stream(stream);

        }



        void schedule_task(uint64_t index){
            //To do list:
            //schedule the task, following is the strategy offload all to GPU

            stoped[lcore_id] = steady_clock_type::now();
            auto elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time)  printf("Enqueuing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            if(print_time) std::cout<<"cuda_stream:"<<stream<<" lcore:"<<lcore_id<<std::endl;
            started[lcore_id] = steady_clock_type::now();

            if(_flows[!index].empty()==false){

                started[lcore_id] = steady_clock_type::now();

                gpu_memcpy_async_d2h(gpu_pkts[!index],dev_gpu_pkts,pre_ngpu_pkts,stream);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)  printf("lcore_id: %d Memcpy pkt device to host time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                gpu_memcpy_async_d2h(gpu_states[!index],dev_gpu_states,pre_ngpu_states,stream);


                //gpu_memcpy_async_d2h(gpu_pkts[!index],dev_gpu_pkts,pre_ngpu_pkts,stream);
                //gpu_memcpy_async_d2h(gpu_states[!index],dev_gpu_states,pre_ngpu_states,stream);
                stoped[lcore_id] = steady_clock_type::now();
                auto elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)  printf("lcore_id: %d Memcpy state device to host time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

            }



            //for(unsigned int i=0;i<_flows[index].size();i=i+1){
                //std::cout<<_flows[index][i]->packets[index].size()<<" ";
            //}
            //std::cout<<"end before sort"<<std::endl;
            started[lcore_id] = steady_clock_type::now();
            int partition=0;
            if(_batch_size!=1){
                sort(_flows[index].begin(),_flows[index].end(),CompLess);
                partition=get_partition(index);
                //partition=_flows[index].size()*5/6;
                if(print_time)std::cout<<"Total flow_num:"<<_flows[index].size()<<std::endl;
                if(print_time)printf("partition: %d\n",partition);
            }
            assert(partition!=-1);

            stoped[lcore_id] = steady_clock_type::now();
            elapsed = stoped[lcore_id] - started[lcore_id];
            if(print_time)printf("Scheduling time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();

            if(partition>0){

                int max_pkt_num_per_flow=_flows[index][partition-1]->packets[index].size();
                int ngpu_pkts = partition * max_pkt_num_per_flow * sizeof(PKT);
                if(print_time)std::cout<<"ngpu_pkts:"<<ngpu_pkts/sizeof(PKT)<<std::endl;
                int ngpu_states = partition * sizeof(ips_flow_state);
                gpu_pkts[index] = (PKT*)malloc(ngpu_pkts);
                gpu_states[index] = (ips_flow_state*)malloc(ngpu_states);
            //    gpu_malloc_host((void**)&gpu_pkts[index],ngpu_pkts);
			//	gpu_malloc_host((void**)&gpu_states[index],ngpu_states);


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
                    if(print_time)  printf("Sync time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

//#pragma omp parallel for
                  //  {
                        for(int i = 0; i < pre_partition; i++){
                            //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                            //assert(gpu_states[!index][i]._dfa_id<200);
                            rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(ips_flow_state));

                            for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                                rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                            }
                        }
                  //  }







                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("Copyback time: %f\n", static_cast<double>(elapsed.count() / 1.0));
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

                    rte_memcpy(&gpu_states[index][i],&(_flows[index][i]->_fs),sizeof(ips_flow_state));
                    //assert(gpu_states[index][i]._dfa_id<200);

                }

                pre_ngpu_pkts=ngpu_pkts;
                pre_ngpu_states=ngpu_states;
                pre_max_pkt_num_per_flow=max_pkt_num_per_flow;
                pre_partition=partition;

                dev_gpu_pkts=_cuda_mem_allocator.gpu_pkt_batch_alloc(ngpu_pkts/sizeof(PKT));
                dev_gpu_states=_cuda_mem_allocator.gpu_state_batch_alloc(ngpu_states/sizeof(ips_flow_state));
                assert(dev_gpu_pkts!=nullptr&&dev_gpu_states!=nullptr);






                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("Batching state time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);

                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore %d Memcpy pkt to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);


                //gpu_memcpy_async_h2d(dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream);
                //gpu_memcpy_async_h2d(dev_gpu_states,gpu_states[index],ngpu_states,stream);
                //std::thread t1(batch_copy2device,dev_gpu_pkts,gpu_pkts[index],ngpu_pkts,stream,dev_gpu_states,gpu_states[index],ngpu_states);
                //t1.detach();
                stoped[lcore_id] = steady_clock_type::now();
                elapsed = stoped[lcore_id] - started[lcore_id];
                if(print_time)printf("lcore %d Memcpy state to device time: %f\n", lcore_id,static_cast<double>(elapsed.count() / 1.0));
                started[lcore_id] = steady_clock_type::now();

                //printf("----gpu_pkts = %p, ngpu_pkts = %d, gpu_pkts[0] = %p\n", gpu_pkts, ngpu_pkts, gpu_pkts[0]);

                /////////////////////////////////////////////
                // Launch kernel

                gpu_launch((char *)dev_gpu_pkts, (char *)dev_gpu_states, (char *)(_flows[0][index]->_f.ips->gpu_ips), max_pkt_num_per_flow, partition,stream);



            }else{
                if(_flows[!index].empty()==false){


                    started[lcore_id] = steady_clock_type::now();
                    //gpu_sync(stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("Sync time: %f\n", static_cast<double>(elapsed.count() / 1.0));
                    started[lcore_id] = steady_clock_type::now();

                    for(int i = 0; i < pre_partition; i++){
                        //std::cout<<"CPU_RCV: gpu_states["<<i<<"].dfa_id:"<<gpu_states[i]._dfa_id<<std::endl;
                        //assert(gpu_states[!index][i]._dfa_id<200);
                        rte_memcpy(&(_flows[!index][i]->_fs),&gpu_states[!index][i],sizeof(ips_flow_state));

                        for(int j = 0; j < (int)_flows[!index][i]->packets[!index].size(); j++){
                            rte_memcpy(reinterpret_cast<char*>(_flows[!index][i]->packets[!index][j].get_header<ether_hdr>(0)),gpu_pkts[!index][i*(pre_max_pkt_num_per_flow)+j].pkt,_flows[!index][i]->packets[!index][j].len());
                        }
                    }
                    gpu_memset_async(dev_gpu_pkts,0, pre_ngpu_pkts,stream);
                    gpu_memset_async(dev_gpu_states,0, pre_ngpu_states,stream);
                    stoped[lcore_id] = steady_clock_type::now();
                    elapsed = stoped[lcore_id] - started[lcore_id];
                    if(print_time)  printf("Copyback time: %f\n", static_cast<double>(elapsed.count() / 1.0));
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
            if(print_time)printf("CPU processing time: %f\n", static_cast<double>(elapsed.count() / 1.0));
            started[lcore_id] = steady_clock_type::now();


        }
        uint64_t get_partition(uint64_t index){

            float processing_time=0;
            float min_processing_time=10000000;
            float cpu_processing_num=0;
            float pre_cpu_processing_num=0;


            for(int i=_flows[index].size();i>=0;i--){
                float cpu_time=0;
                float gpu_time=0;
                if(i>0)
                    gpu_time=_flows[index][i-1]->packets[index].size();
                for(unsigned int j=i;j<_flows[index].size();j++){
                    cpu_time+=_flows[index][j]->packets[index].size();
                }
                processing_time=std::max(gpu_time,cpu_time/COMPUTE_RATIO);
                pre_cpu_processing_num=cpu_processing_num;
                cpu_processing_num=cpu_time;
                if(processing_time>=min_processing_time){
                    if(print_time)std::cout<<"cpu_pkts_processed: "<<pre_cpu_processing_num<<std::endl;
                    if(i==0){
                        if(print_time)    std::cout<<"GPU_max_pkt: "<<0<<std::endl;
                        return 0;
                    }else{
                        if(print_time)   std::cout<<"GPU_max_pkt: "<<_flows[index][i]->packets[index].size()<<std::endl;
                        return i+1;
                    }
                    //std::cout<<"    min_processing_time:"<<*result<<std::endl;


                }else{
                    min_processing_time=processing_time;
                }

            }
            return 0;
        }

    };

struct flow_key{
        uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
        flow_key(uint32_t saddr,uint32_t daddr, uint16_t sport, uint16_t dport):saddr(saddr),daddr(daddr),sport(sport),dport(dport){

        }
    };
struct HashFunc
{
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

struct EqualKey
{
    bool operator () (const flow_key &lhs, const flow_key &rhs) const
    {
        return lhs.saddr  == rhs.saddr
            && lhs.daddr == rhs.daddr
            && lhs.sport  == rhs.sport
            && lhs.dport == rhs.dport;
    }
};
public:
    static IPS* ips;
    batch _batch;
    uint64_t _pkt_counter;
    uint16_t _port_id;
    uint16_t _queue_id;
    uint16_t _lcore_id;
    std::vector<rte_mbuf*> _send_buffer;
    std::unordered_map<flow_key,flow_operator*,HashFunc,EqualKey> _flow_table;

};






#endif /* SAMPLES_L2_FORWARD_IPS_HH_ */
