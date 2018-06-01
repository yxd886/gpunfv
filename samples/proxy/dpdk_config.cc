/*
 * dpdk_config.cc
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */




#include "../include/dpdk_config.hh"


uint64_t _batch_size=1;
int core_num;
uint64_t schedule = 0;
uint64_t print_time = 0;
uint64_t print_simple_time = 0;
uint64_t gpu_time = 0;
uint64_t schedule_timer_tsc[10] ={ 0};

bool dynamic_adjust = false;





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



int parse_batchsize(const char *portmask){
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 10);


    return pm;
}



int parse_args(int argc, char **argv){
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {CMD_LINE_OPT_PRINT_TIME, 0, 0, 0},
        {CMD_LINE_OPT_PRINT_SIMPLE_TIME, 0, 0, 0},
        {CMD_LINE_OPT_GPU_TIME, 0, 0, 0},
        {CMD_LINE_OPT_SCHEDULE,0,0,0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "b:c:P",
                lgopts, &option_index)) != EOF) {

        switch (opt) {
        case 'b':
            _batch_size = parse_batchsize(optarg);
            if (_batch_size == 1) {
                //printf("invalid _batch_size\n");
                //print_usage(prgname);
                //return -1;
                _batch_size = 10000;
                dynamic_adjust = true;
            }
            break;
        case 'c':
            core_num = parse_batchsize(optarg);
            break;
        case 'P':
            printf("Promiscuous mode selected\n");
            promiscuous_on = 1;
            break;

        /* long options */
        case 0:

            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_PRINT_TIME,
                sizeof(CMD_LINE_OPT_PRINT_TIME))) {
                  print_time=1;
            }
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_PRINT_SIMPLE_TIME,
                sizeof(CMD_LINE_OPT_PRINT_SIMPLE_TIME))) {
                  print_simple_time=1;
            }
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_GPU_TIME,
                sizeof(CMD_LINE_OPT_GPU_TIME))) {
                  gpu_time=1;
            }
            if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_SCHEDULE,
                sizeof(CMD_LINE_OPT_SCHEDULE))) {
                  schedule=1;
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


