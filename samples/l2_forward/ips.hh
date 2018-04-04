/*
 * ips.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef SAMPLES_L2_FORWARD_IPS_HH_
#define SAMPLES_L2_FORWARD_IPS_HH_
#include "../gpu_interface.hh"

class IPS{
public:
    IPS(){

        int num_patterns, i;

        int num_threads = 1;
        assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        // Map ips object
        //gpu_mem_map(this, sizeof(IPS));
        gpu_malloc((void**)(&gpu_ips), sizeof(IPS));

        //gpu map
        //gpu_mem_map(stats,num_threads * sizeof(struct stat_t));
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
           // gpu_mem_map(dfa_arr[i].root,AHO_MAX_STATES * sizeof(struct aho_state));
           // gpu_malloc((void**)(&dev_stats),num_threads * sizeof(struct stat_t));
           // gpu_memcpy_async_h2d(dev_stats,stats,num_threads * sizeof(struct stat_t));
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



        //gpu_mem_unmap(stats);
       // gpu_mem_unmap(this);
        free(stats);
    }
    struct aho_dfa dfa_arr[AHO_MAX_DFA];
    struct stat_t *stats;
    IPS *gpu_ips;

};


#endif /* SAMPLES_L2_FORWARD_IPS_HH_ */
