//GPUNFV system include file
#include "../include/dpdk_config.hh"
#include "../include/rte_packet.hh"
#include "forwarder.hh"

extern uint64_t timer_period;
extern uint64_t schedule_period;
extern uint64_t schedule_timer_tsc[10];
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/*
  This example code shows how to write an (optionally encrypting) SSL proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
extern"C"{
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "util-internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "openssl-compat.h"

}

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;
static int use_wrapper = 1;

static SSL_CTX *ssl_ctx = NULL;

#define MAX_OUTPUT (512*1024)

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

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
    forwarder flow_forwarder(qconf->rx_queue_list[0].port_id,qconf->rx_queue_list[0].queue_id,lcore_id);


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




static void
readcb(struct bufferevent *bev, void *ctx)
{
    //printf("readcb\n");
    struct bufferevent *partner = (struct bufferevent *)ctx;
    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);
    if (!partner) {
        evbuffer_drain(src, len);
        return;
    }
    dst = bufferevent_get_output(partner);
    //evbuffer_add_buffer(dst, src);
    char msg[4096];
    size_t leng = 0;
    leng=bufferevent_read(bev,msg,4096);
    printf("recv %d bytes\n",leng);
    bufferevent_write(partner,msg,leng);

    if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        /* We're giving the other side data faster than it can
         * pass it on.  Stop reading here until we have drained the
         * other side to MAX_OUTPUT/2 bytes. */
        bufferevent_setcb(partner, readcb, drained_writecb,
            eventcb, bev);
        bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
            MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
    }
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
    struct bufferevent *partner = (struct bufferevent *)ctx;

    /* We were choking the other side until we drained our outbuf a bit.
     * Now it seems drained. */
    bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (partner)
        bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *b = bufferevent_get_output(bev);

    if (evbuffer_get_length(b) == 0) {
        bufferevent_free(bev);
    }
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
    struct bufferevent *partner = (struct bufferevent *)ctx;

    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
        if (what & BEV_EVENT_ERROR) {
            unsigned long err;
            while ((err = (bufferevent_get_openssl_error(bev)))) {
                const char *msg = (const char*)
                    ERR_reason_error_string(err);
                const char *lib = (const char*)
                    ERR_lib_error_string(err);
                const char *func = (const char*)
                    ERR_func_error_string(err);
                fprintf(stderr,
                    "%s in %s %s\n", msg, lib, func);
            }
            if (errno)
                perror("connection error");
        }

        if (partner) {
            /* Flush all pending data */
            readcb(bev, ctx);

            if (evbuffer_get_length(
                    bufferevent_get_output(partner))) {
                /* We still have to flush data from the other
                 * side, but when that's done, close the other
                 * side. */
                bufferevent_setcb(partner,
                    NULL, close_on_finished_writecb,
                    eventcb, NULL);
                bufferevent_disable(partner, EV_READ);
            } else {
                /* We have nothing left to say to the other
                 * side; close it. */
                bufferevent_free(partner);
            }
        }
        bufferevent_free(bev);
    }
}

static void
syntax(void)
{
    fputs("Syntax:\n", stderr);
    fputs("   le-proxy [-s] [-W] <listen-on-addr> <connect-to-addr>\n", stderr);
    fputs("Example:\n", stderr);
    fputs("   le-proxy 127.0.0.1:8888 1.2.3.4:80\n", stderr);

    exit(1);
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
    struct bufferevent *b_out, *b_in;
    /* Create two linked bufferevent objects: one to connect, one for the
     * new connection */
    b_in = bufferevent_socket_new(base, fd,
        BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

    if (!ssl_ctx || use_wrapper)
        b_out = bufferevent_socket_new(base, -1,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    else {
        SSL *ssl = SSL_new(ssl_ctx);
        b_out = bufferevent_openssl_socket_new(base, -1, ssl,
            BUFFEREVENT_SSL_CONNECTING,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

    assert(b_in && b_out);

    if (bufferevent_socket_connect(b_out,
        (struct sockaddr*)&connect_to_addr, connect_to_addrlen)<0) {
        perror("bufferevent_socket_connect");
        bufferevent_free(b_out);
        bufferevent_free(b_in);
        return;
    }

    if (ssl_ctx && use_wrapper) {
        struct bufferevent *b_ssl;
        SSL *ssl = SSL_new(ssl_ctx);
        b_ssl = bufferevent_openssl_filter_new(base,
            b_out, ssl, BUFFEREVENT_SSL_CONNECTING,
            BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        if (!b_ssl) {
            perror("Bufferevent_openssl_new");
            bufferevent_free(b_out);
            bufferevent_free(b_in);
            return;
        }
        b_out = b_ssl;
    }

    bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
    bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

    bufferevent_enable(b_in, EV_READ|EV_WRITE);
    bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

int
main(int argc, char **argv)
{
    int i;
    int socklen;
    forwarder::_nf = new NF;

    int use_ssl = 0;
    struct evconnlistener *listener;

    if (argc < 3)
        syntax();

    for (i=1; i < argc; ++i) {
        if (!strcmp(argv[i], "-s")) {
            use_ssl = 1;
        } else if (!strcmp(argv[i], "-W")) {
            use_wrapper = 0;
        } else if (argv[i][0] == '-') {
            syntax();
        } else
            break;
    }

    if (i+2 != argc)
        syntax();

    memset(&listen_on_addr, 0, sizeof(listen_on_addr));
    socklen = sizeof(listen_on_addr);
    if (evutil_parse_sockaddr_port(argv[i],
        (struct sockaddr*)&listen_on_addr, &socklen)<0) {
        int p = atoi(argv[i]);
        struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
        if (p < 1 || p > 65535)
            syntax();
        sin->sin_port = htons(p);
        sin->sin_addr.s_addr = htonl(0x7f000001);
        sin->sin_family = AF_INET;
        socklen = sizeof(struct sockaddr_in);
    }

    memset(&connect_to_addr, 0, sizeof(connect_to_addr));
    connect_to_addrlen = sizeof(connect_to_addr);
    if (evutil_parse_sockaddr_port(argv[i+1],
        (struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0)
        syntax();

    base = event_base_new();
    if (!base) {
        perror("event_base_new()");
        return 1;
    }

    if (use_ssl) {
        int r;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
        SSL_library_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#endif
        r = RAND_poll();
        if (r == 0) {
            fprintf(stderr, "RAND_poll() failed.\n");
            return 1;
        }
        ssl_ctx = SSL_CTX_new(TLS_method());
    }

    listener = evconnlistener_new_bind(base, accept_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
        -1, (struct sockaddr*)&listen_on_addr, socklen);

    if (! listener) {
        fprintf(stderr, "Couldn't open listener.\n");
        event_base_free(base);
        return 1;
    }
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);



  /*  unsigned lcore_id;


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
     // launch per-lcore init on every lcore
     rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
     RTE_LCORE_FOREACH_SLAVE(lcore_id) {
         if (rte_eal_wait_lcore(lcore_id) < 0)
             return -1;
     }
*/

    return 0;
}

