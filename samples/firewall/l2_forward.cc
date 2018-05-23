//GPUNFV system include file
#include "../include/dpdk_config.hh"
#include "../include/rte_packet.hh"
#include "forwarder.hh"

extern uint64_t timer_period;
extern uint64_t schedule_period;
extern uint64_t schedule_timer_tsc[10];
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];


//user defined NF include file


static void
l2fwd_main_loop(void)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    unsigned i, portid, nb_rx, send, queueid;
    struct lcore_conf *qconf;
    uint64_t cur_tsc,diff_tsc,prev_tsc,timer_tsc;


    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];

    prev_tsc = rte_rdtsc();
    timer_tsc=0;
    schedule_timer_tsc[lcore_id]=0;

    if (qconf->n_rx_queue == 0) {

        return;
    }
    forwarder flow_forwarder(!qconf->rx_queue_list[0],qconf->tx_queue_id[!qconf->rx_queue_list[0]],lcore_id);
    //forwarder flow_forwarder(qconf->rx_queue_list[1].port_id,qconf->rx_queue_list[1].queue_id,lcore_id);


    while (1) {



        cur_tsc = rte_rdtsc();

        diff_tsc = cur_tsc - prev_tsc;

        timer_tsc += diff_tsc;
        schedule_timer_tsc[lcore_id]+=diff_tsc;

        /* if print timer has reached its timeout */
        if (unlikely(timer_tsc >= timer_period)) {

            /* do this only on master core */
            if (lcore_id == 0&&flow_forwarder._batch._profileing==false) {

                print_stats();
                /* reset the timer */

            }
            timer_tsc = 0;
        }

        /* if schedule timer has reached its timeout */
        if (unlikely(schedule_timer_tsc[lcore_id] >= schedule_period)) {

        	  schedule_timer_tsc[lcore_id] = 0;
        	  /* reset the timer */

        	  flow_forwarder.time_trigger_schedule();


        }

        prev_tsc = cur_tsc;

        /*
         * Read packet from RX queues
         */

        for (i = 0; i < qconf->n_rx_queue; i++) {

            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;

            nb_rx = receive_burst(portid, queueid,lcore_id,
                         pkts_burst);


            for(int i=0;i<nb_rx;i++){
                flow_forwarder.dispath_flow(std::move(rte_packet(pkts_burst[i])));
            }

        }
    }
}

/* main processing loop */
static int
main_loop(__attribute__((unused)) void *dummy)
{
  printf("locre\n");
  l2fwd_main_loop();
  return 0;
}

NF *forwarder::_nf = nullptr;

int
main(int argc, char **argv)
{
    unsigned lcore_id;


    cudaDeviceProp prop;
    int dev;
    cudaGetDevice(&dev);
    cudaGetDeviceProperties(&prop,dev);
    printf("deviceOverlap :%d\n",prop.deviceOverlap);
    if(!prop.deviceOverlap)
    {
            printf("Device doesn't support overlap\n");
            return 0;
    }

    dpdk_config(argc,argv);
    forwarder::_nf = new NF;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}
