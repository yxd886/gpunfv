/*
 * dpdk_config.cc
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */




#include "dpdk_config.hh"


uint64_t _batch_size=1;
uint64_t print_time = 0;

uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

__m128i val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask = 0;
int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
int numa_on = 0; /**< NUMA is enabled by default. */

uint64_t timer_period = 1;

struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

struct lcore_params * lcore_params = lcore_params_array_default;
uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
                sizeof(lcore_params_array_default[0]);

struct rte_eth_conf port_conf;

struct rte_mempool * pktmbuf_pool[NB_SOCKETS];
struct  timeval    tv;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

uint64_t pre_total_rx;
uint64_t pre_total_tx;
uint64_t pre_total_drop;


uint64_t pre_rx[10];
uint64_t pre_tx[10];
uint64_t pre_dropped[10];

struct port_statistics statistics[RTE_MAX_ETHPORTS][10];

void send_brust(uint8_t _port_id, uint8_t _queue_id, uint16_t lcore_id, rte_mbuf** pkt_buffer){

    statistics[_port_id][lcore_id].tx+=MAX_PKT_BURST;
    int ret=rte_eth_tx_burst(_port_id,_queue_id,pkt_buffer,MAX_PKT_BURST);

    if(ret<MAX_PKT_BURST){
        for(int i=ret;i<MAX_PKT_BURST;i++){
            rte_pktmbuf_free(pkt_buffer[i]);
        }
    }
}
uint16_t receive_burst(uint8_t _port_id, uint8_t _queue_id, uint16_t lcore_id, rte_mbuf** pkt_buffer){


    uint16_t nb_rx = rte_eth_rx_burst(_port_id, _queue_id,
            pkt_buffer, MAX_PKT_BURST);
   /* if(nb_rx)
        std::cout<<"nb_rx  :"<<nb_rx<<" lcore_id: "<<lcore_id<<std::endl;*/

    statistics[_port_id][lcore_id].rx+=nb_rx;
    return nb_rx;
}


int check_lcore_params(void){
    uint8_t queue, lcore;
    uint16_t i;
    int socketid;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("invalid queue number: %hhu\n", queue);
            return -1;
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
            return -1;
        }
        if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
            (numa_on == 0)) {
            printf("warning: lcore %hhu is on socket %d with numa off \n",
                lcore, socketid);
        }
    }
    return 0;
}


int check_port_config(const unsigned nb_ports){
    unsigned portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (portid >= nb_ports) {
            printf("port %u is not present on the board\n", portid);
            return -1;
        }
    }
    return 0;
}


uint8_t get_port_n_rx_queues(const uint8_t port){
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port && lcore_params[i].queue_id > queue)
            queue = lcore_params[i].queue_id;
    }
    return (uint8_t)(++queue);
}


int init_lcore_rx_queues(void){
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                (unsigned)nb_rx_queue + 1, (unsigned)lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            lcore_conf[lcore].n_rx_queue++;
        }
    }
    return 0;
}


void print_usage(const char *prgname){
    printf ("%s [EAL options] -- -p PORTMASK -P"
        "  [--config (port,queue,lcore)[,(port,queue,lcore]]"
        "  [--enable-jumbo [--max-pkt-len PKTLEN]]\n"
        "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
        "  -b GPU_BATCH_SIZE: set gpu_batch_size, default disable GPU"
        "\n"
        "  -P : enable promiscuous mode\n"
        "  --config (port,queue,lcore): rx queues configuration\n"
        "  --eth-dest=X,MM:MM:MM:MM:MM:MM: optional, ethernet destination for port X\n"
        "  --no-numa: optional, disable numa awareness\n"
        "  --ipv6: optional, specify it if running ipv6 packets\n"
        "  --enable-jumbo: enable jumbo frame"
        " which max packet len is PKTLEN in decimal (64-9600)\n"
        "  --hash-entry-num: specify the hash entry number in hexadecimal to be setup\n",
        prgname);
}


int parse_max_pkt_len(const char *pktlen){
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}


int parse_batchsize(const char *portmask){
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 10);


    return pm;
}

int parse_portmask(const char *portmask){
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

int parse_config(const char *q_arg){
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;

    nb_lcore_params = 0;

    while ((p = strchr(p0,'(')) != NULL) {
        ++p;
        if((p0 = strchr(p,')')) == NULL)
            return -1;

        size = p0 - p;
        if(size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++){
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                nb_lcore_params);
            return -1;
        }
        lcore_params_array[nb_lcore_params].port_id = (uint8_t)int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id = (uint8_t)int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id = (uint8_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;
    return 0;
}


void parse_eth_dest(const char *optarg){
    uint8_t portid;
    char *port_end;
    uint8_t c, *dest, peer_addr[6];

    errno = 0;
    portid = strtoul(optarg, &port_end, 10);
    if (errno != 0 || port_end == optarg || *port_end++ != ',')
        rte_exit(EXIT_FAILURE,
        "Invalid eth-dest: %s", optarg);
    if (portid >= RTE_MAX_ETHPORTS)
        rte_exit(EXIT_FAILURE,
        "eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
        portid, RTE_MAX_ETHPORTS);

    if (cmdline_parse_etheraddr(NULL, port_end,
        &peer_addr, sizeof(peer_addr)) < 0)
        rte_exit(EXIT_FAILURE,
        "Invalid ethernet address: %s\n",
        port_end);
    dest = (uint8_t *)&dest_eth_addr[portid];
    for (c = 0; c < 6; c++)
        dest[c] = peer_addr[c];
    *(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
}


int parse_args(int argc, char **argv){
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {CMD_LINE_OPT_CONFIG, 1, 0, 0},
        {CMD_LINE_OPT_ETH_DEST, 1, 0, 0},
        {CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
        {CMD_LINE_OPT_IPV6, 0, 0, 0},
        {CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
        {CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, 0},
        {CMD_LINE_OPT_PRINT_TIME, 0, 0, 0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:b:P",
                lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 'b':
            _batch_size = parse_batchsize(optarg);
            if (_batch_size == 1) {
                printf("invalid _batch_size\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 'P':
            printf("Promiscuous mode selected\n");
            promiscuous_on = 1;
            break;

        /* long options */
        case 0:
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG,
                sizeof (CMD_LINE_OPT_CONFIG))) {
                ret = parse_config(optarg);
                if (ret) {
                    printf("invalid config\n");
                    print_usage(prgname);
                    return -1;
                }
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ETH_DEST,
                sizeof(CMD_LINE_OPT_CONFIG))) {
                    parse_eth_dest(optarg);
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
                sizeof(CMD_LINE_OPT_NO_NUMA))) {
                printf("numa is disabled \n");
                numa_on = 0;
            }
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_PRINT_TIME,
                sizeof(CMD_LINE_OPT_PRINT_TIME))) {
                  print_time=1;
            }

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_ENABLE_JUMBO,
                sizeof (CMD_LINE_OPT_ENABLE_JUMBO))) {
                struct option lenopts = {"max-pkt-len", required_argument, 0, 0};

                printf("jumbo frame is enabled - disabling simple TX path\n");
                port_conf.rxmode.jumbo_frame = 1;

                /* if no max-pkt-len set, use the default value ETHER_MAX_LEN */
                if (0 == getopt_long(argc, argvopt, "", &lenopts, &option_index)) {
                    ret = parse_max_pkt_len(optarg);
                    if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)){
                        printf("invalid packet length\n");
                        print_usage(prgname);
                        return -1;
                    }
                    port_conf.rxmode.max_rx_pkt_len = ret;
                }
                printf("set jumbo frame max packet length to %u\n",
                        (unsigned int)port_conf.rxmode.max_rx_pkt_len);
            }
            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}

void print_ethaddr(const char *name, const struct ether_addr *eth_addr){
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}


void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask){
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)portid,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                        (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}



int init_mem(unsigned nb_mbuf){
    struct lcore_conf *qconf;
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
                socketid, lcore_id, NB_SOCKETS);
        }
        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                        "Cannot init mbuf pool on socket %d\n", socketid);
            else{
                printf("Allocated mbuf pool on socket %d\n", socketid);
                //rte_mempool_obj_iter(pktmbuf_pool[socketid],my_obj_init,NULL);
            }


        }
        qconf = &lcore_conf[lcore_id];
        qconf->ipv4_lookup_struct = ipv4_l3fwd_lookup_struct[socketid];
        qconf->ipv6_lookup_struct = ipv6_l3fwd_lookup_struct[socketid];
    }
    return 0;
}



void print_stats(void){
    uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
    unsigned portid;

    total_packets_dropped = 0;
    total_packets_tx = 0;
    total_packets_rx = 0;
    uint64_t packets_rx[10]={0};
    uint64_t packets_tx[10]={0};
    uint64_t packets_dropped[10]={0};


    printf("-------------------------------------------------------------------------------");
    for(unsigned i =0; i<RTE_MAX_LCORE; i++){
        if (rte_lcore_is_enabled(i) == 0)
            continue;
        total_packets_dropped += statistics[portid][i].dropped;
        total_packets_tx += statistics[portid][i].tx;
        total_packets_rx += statistics[portid][i].rx;
        packets_rx[i]=statistics[portid][i].rx-pre_rx[i];
        packets_tx[i]=statistics[portid][i].tx-pre_tx[i];
        packets_dropped[i]=statistics[portid][i].dropped-pre_dropped[i];
        printf("lcore %d Packets sent rate: %8d Packets received rate: %8d Packets dropped: %8d\n",
               i,
               packets_tx[i],
               packets_rx[i],
               packets_dropped[i]);
        pre_dropped[i]=statistics[portid][i].dropped;
        pre_tx[i]=statistics[portid][i].tx;
        pre_rx[i]=statistics[portid][i].rx;
    }
        /* skip disabled ports */


    printf("Total Packets sent rate: %8d Packets received rate: %8d Packets dropped: %8d\n",
           total_packets_tx-pre_total_tx,
           total_packets_rx-pre_total_rx,
           total_packets_dropped-pre_total_drop);
    printf("-------------------------------------------------------------------------------");


    pre_total_tx=total_packets_tx;
    pre_total_drop=total_packets_dropped;
    pre_total_rx=total_packets_rx;
}

void dpdk_config(int argc, char** argv){
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

}
