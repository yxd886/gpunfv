


//GPUNFV system include file
#include "l2_forward.hh"
#include "rte_packet.hh"


/* Send burst of packets on an output interface */


std::chrono::time_point<std::chrono::steady_clock> started;
std::chrono::time_point<std::chrono::steady_clock> stoped;
using namespace std::chrono;
using steady_clock_type = std::chrono::steady_clock;



//user defined NF include file
#include "ips.hh"




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

    if (qconf->n_rx_queue == 0) {

        return;
    }
    forwarder flow_forwarder(qconf->rx_queue_list[0].port_id,qconf->rx_queue_list[0].queue_id,lcore_id);


    while (1) {



        cur_tsc = rte_rdtsc();
        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;

        /* if timer is enabled */

            /* advance the timer */
        timer_tsc += diff_tsc;
        //printf("timer_period: %18"PRIu64"\n",timer_period);

        /* if timer has reached its timeout */
        if (unlikely(timer_tsc >= timer_period)) {

            /* do this only on master core */
            if (lcore_id == 0) {
                print_stats();
                /* reset the timer */

            }
            timer_tsc = 0;
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



IPS * forwarder::ips = nullptr;

int
main(int argc, char **argv)
{


    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
    port_conf.rxmode.split_hdr_size = 0;
    port_conf.rxmode.header_split   = 0;
    port_conf.rxmode.hw_ip_checksum = 1;
    port_conf.rxmode.hw_vlan_filter = 0;
    port_conf.rxmode.jumbo_frame    = 0;
    port_conf.rxmode.hw_strip_crc   = 0;
    port_conf.rx_adv_conf.rss_conf.rss_key   = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP|ETH_RSS_UDP|ETH_RSS_TCP;
    port_conf.txmode.mq_mode=ETH_MQ_TX_NONE;


    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    int ret;
    unsigned nb_ports;
    uint16_t queueid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t portid, nb_rx_queue, queue, socketid;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
    for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
        dest_eth_addr[portid] = ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
        *(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
    }
    timer_period =rte_get_timer_hz();

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count();
    if (nb_ports > RTE_MAX_ETHPORTS)
        nb_ports = RTE_MAX_ETHPORTS;
    printf("nb_ports:%d\n",nb_ports);
    if (check_port_config(nb_ports) < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();

    /* initialize all ports */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %d ... ", portid );
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = nb_lcores;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
            nb_rx_queue, (unsigned)n_tx_queue );
        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                    (uint16_t)n_tx_queue, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr(" Address:", &ports_eth_addr[portid]);
        printf(", ");
        print_ethaddr("Destination:",
            (const struct ether_addr *)&dest_eth_addr[portid]);
        printf(", ");

        /*
         * prepare src MACs for each port.
         */
        ether_addr_copy(&ports_eth_addr[portid],
            (struct ether_addr *)(val_eth + portid) + 1);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            rte_eth_dev_info_get(portid, &dev_info);
            txconf = &dev_info.default_txconf;
            if (port_conf.rxmode.jumbo_frame)
                txconf->txq_flags = 0;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             socketid, txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
                    "port=%d\n", ret, portid);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id );
        fflush(stdout);
        /* init RX queues */
        for(queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

            if (numa_on)
                socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    socketid,
                    NULL,
                    pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d,"
                        "port=%d\n", ret, portid);
        }
    }

    printf("\n");

    /* start ports */
    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
                ret, portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

    //int* a = (int*)malloc(sizeof(int)*3);
    //assert(a!=NULL);

    forwarder::ips=new IPS;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}
