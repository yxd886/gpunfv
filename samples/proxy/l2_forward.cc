//GPUNFV system include file

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
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
extern"C"{
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event_struct.h>

#include "util-internal.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "openssl-compat.h"

}
#include "../include/dpdk_config.hh"
#include "../include/rte_packet.hh"
#include "../include/message.hh"
#include "forwarder.hh"

extern uint64_t timer_period;
extern uint64_t schedule_period;
extern uint64_t schedule_timer_tsc[10];
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];
extern int core_num;

static int use_wrapper = 1;
uint64_t g_throughput[10];
uint64_t pre_g_throughput[10];

static SSL_CTX *ssl_ctx = NULL;

#define MAX_OUTPUT (512*1024)

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

//user defined NF include file

NF *forwarder::_nf = nullptr;

class cb_arg{
public:
    cb_arg(struct bufferevent* bev,bool is_client,forwarder* f):bev(bev),is_client(is_client),f(f){

    }
    struct bufferevent* bev;
    bool is_client;
    forwarder* f;
};

char msg_tmp[4096+sizeof(size_t)];
static void
readcb(struct bufferevent *bev, void *ctx)
{
    //printf("readcb\n");
    cb_arg* arg = (cb_arg *)ctx;
    struct bufferevent *partner = arg->bev;
    /*if(arg->is_client){
        printf("from client\n");
    }else{
        printf("from server\n");
    }*/

    struct evbuffer *src, *dst;
    size_t len;
    src = bufferevent_get_input(bev);
    len = evbuffer_get_length(src);
   // printf("recv buffer len:%d\n",len);
    if (!partner) {
        evbuffer_drain(src, len);
        return;
    }
    dst = bufferevent_get_output(partner);
    //evbuffer_add_buffer(dst, src);
    char* msg=(char*)malloc((4096+sizeof(size_t))*sizeof(char));
    size_t leng = 0;
    leng=bufferevent_read(bev,msg+sizeof(size_t),4096);
  //  printf("recv %d bytes\n",leng);
    //bufferevent_write(partner,msg,leng);
    if(leng&&arg->is_client){
        *((size_t*)msg) = leng;
        arg->f->dispath_flow(std::move(message(msg,((leng+sizeof(size_t)+sizeof(size_t)-1)/sizeof(size_t))*sizeof(size_t))),arg->is_client,bev,partner);

    }else{
        bufferevent_write(partner,msg+sizeof(size_t),leng);
    }
    //bufferevent_write(partner,msg_tmp+sizeof(size_t),leng);

    if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        //We're giving the other side data faster than it can
        //pass it on.  Stop reading here until we have drained the
        // other side to MAX_OUTPUT/2 bytes.
        bufferevent_setcb(partner, readcb, drained_writecb,
            eventcb, new cb_arg(bev,!arg->is_client,arg->f));
        bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
            MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
    }
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
    cb_arg* arg = (cb_arg *)ctx;
    struct bufferevent *partner = arg->bev;

    /* We were choking the other side until we drained our outbuf a bit.
     * Now it seems drained. */
    bufferevent_setcb(bev, readcb, NULL, eventcb, new cb_arg(partner,arg->is_client,arg->f));
    bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
    if (partner)
        bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *b = bufferevent_get_output(bev);
    cb_arg* arg = (cb_arg *)ctx;

    if (evbuffer_get_length(b) == 0) {
        arg->f->_flow_table.erase(bev);
        /* Flush all pending data */
        //printf("remove partner:%x \n",bev);
        bufferevent_free(bev);
        bev = nullptr;

    }
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
    cb_arg* arg = (cb_arg *)ctx;
    struct bufferevent *partner = arg->bev;
    /*if(arg->is_client){
        printf("from client\n");
    }else{
        printf("from server\n");
    }*/

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

            readcb(bev, ctx);

            if (evbuffer_get_length(
                    bufferevent_get_output(partner))) {
                /* We still have to flush data from the other
                 * side, but when that's done, close the other
                 * side. */
                bufferevent_setcb(partner,
                    NULL, close_on_finished_writecb,
                    eventcb, new cb_arg(bev,!arg->is_client,arg->f));
                bufferevent_disable(partner, EV_READ);
            } else {
                /* We have nothing left to say to the other
                 * side; close it. */
                arg->f->_flow_table.erase(partner);
                /* Flush all pending data */
                //printf("remove partner:%x \n",partner);
                bufferevent_free(partner);
                partner = nullptr;
            }

        }
        //printf("remove yourself: %x\n",bev);
        arg->f->_flow_table.erase(bev);
        bufferevent_free(bev);
        bev = nullptr;

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

class accept_arg{
public:
    forwarder* f;
    struct event_base *base;
    struct sockaddr_storage* listen_on_addr;
    struct sockaddr_storage* connect_to_addr;
    int connect_to_addrlen;
    accept_arg(forwarder* f,struct event_base *base,struct sockaddr_storage* listen_on_addr,struct sockaddr_storage* connect_to_addr,int connect_to_addrlen):f(f),base(base),listen_on_addr(listen_on_addr),connect_to_addr(connect_to_addr),connect_to_addrlen(connect_to_addrlen){

    }

};

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
    struct bufferevent *b_out, *b_in;
    /* Create two linked bufferevent objects: one to connect, one for the
     * new connection */

    accept_arg* arg = (accept_arg*)p;
    forwarder* f0 =arg->f;
    struct event_base *base = arg->base;
    struct sockaddr_storage* connect_to_addr = arg->connect_to_addr;
    int connect_to_addrlen = arg->connect_to_addrlen;
    g_throughput[f0->_lcore_id]++;
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
        (struct sockaddr*)connect_to_addr, connect_to_addrlen)<0) {
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

    f0->create_flow_operator(true,b_in,b_out);
    f0->create_flow_operator(false,b_out,b_in);

    bufferevent_setcb(b_in, readcb, NULL, eventcb, new cb_arg(b_out,true,f0));
    bufferevent_setcb(b_out, readcb, NULL, eventcb, new cb_arg(b_in,false,f0));

    bufferevent_enable(b_in, EV_READ|EV_WRITE);
    bufferevent_enable(b_out, EV_READ|EV_WRITE);
    //printf("create client bufferevent: %x\n",b_in);
    //printf("create server bufferevent: %x\n",b_out);
}

class gpu_timer{
public:
    event* ev;
    forwarder* f;
    gpu_timer(event* ev, forwarder* f):ev(ev),f(f){

    }
};

static void timeout_cb(evutil_socket_t fd, short events, void *arg) {

    //printf("timeout trigger\n");
    if(!arg) return;
    gpu_timer* ctx =(gpu_timer*)arg;
    if( ctx->f->_lcore_id==0){
        uint64_t throughput=0;
        for(int i = 0; i<core_num;i++){
            uint64_t per_throughput=0;
            per_throughput= g_throughput[i] - pre_g_throughput[i];
            printf("core_id: %d throughput: %d reqs/s  ",i, per_throughput);
            throughput += per_throughput;
            pre_g_throughput[i] = g_throughput[i];
        }
        printf("Total throughput: %d reqs/s\n", throughput);
    }


    if( ctx->f->_batch._timer_reactivate==false){
        ctx->f->time_trigger_schedule();
    }else{
        ctx->f->_batch._timer_reactivate=false;
    }

    struct event* ev_time = ctx->ev;
    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec=1;
    //tv.tv_sec = 2;

    event_add(ev_time, &tv);

}
static void print_throughput(evutil_socket_t fd, short events, void *arg) {


    struct event* ev_time = (struct event* )arg;
    uint64_t throughput=0;

    for(int i = 0; i<core_num;i++){
        uint64_t per_throughput=0;
        per_throughput= g_throughput[i] - pre_g_throughput[i];
        printf("core_id: %d throughput: %d reqs/s  ",i, per_throughput);
        throughput += per_throughput;
        pre_g_throughput[i] = g_throughput[i];
    }
    printf("Total throughput: %d reqs/s\n", throughput);


    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec=1;
    event_add(ev_time, &tv);

}
int thread_main(int core_id){
    struct event_base *base;
    struct sockaddr_storage listen_on_addr;
    struct sockaddr_storage connect_to_addr;
    int connect_to_addrlen;
    int i;
    int socklen;

    forwarder f0(0,0,core_id);
    f0._batch.lcore_id = core_id;
    string _listen("10.28.0.17:110");
    _listen+=std::to_string(core_id);
    const char *listen_ip=_listen.c_str();
    char connect_ip[]="10.28.0.17:12345";

    int use_ssl = 0;
    struct evconnlistener *listener;

    /*for (i=1; i < argc; ++i) {
        if (!strcmp(argv[i], "-s")) {
            use_ssl = 1;
        } else if (!strcmp(argv[i], "-W")) {
            use_wrapper = 0;
        } else
            break;
    }*/

    memset(&listen_on_addr, 0, sizeof(listen_on_addr));
    socklen = sizeof(listen_on_addr);
    if (evutil_parse_sockaddr_port(listen_ip,
        (struct sockaddr*)&listen_on_addr, &socklen)<0) {
        int p = atoi(listen_ip);
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
    if (evutil_parse_sockaddr_port(connect_ip,
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

    listener = evconnlistener_new_bind(base, accept_cb, new accept_arg(&f0,base,&listen_on_addr,&connect_to_addr,connect_to_addrlen),
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE|LEV_OPT_REUSEABLE_PORT,
        -1, (struct sockaddr*)&listen_on_addr, socklen);

    if (! listener) {
        fprintf(stderr, "Couldn't open listener.\n");
        event_base_free(base);
        return 1;
    }

    struct event ev_time;
    event_assign(&ev_time, base, -1, EV_PERSIST, timeout_cb, (void*) new gpu_timer(&ev_time,&f0));

    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec=1;
    event_add(&ev_time, &tv);
    //evtimer_del(&ev_time);


/*if(core_id==0){
    struct event ev_print_throughput;
    event_assign(&ev_print_throughput, base, -1, EV_PERSIST, print_throughput, (void*)&ev_print_throughput);

    struct timeval tv1;
    evutil_timerclear(&tv1);
    tv1.tv_sec=1;
    event_add(&ev_print_throughput, &tv1);


}*/

    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);

    return 0;
}

int
main(int argc, char **argv)
{

    forwarder::_nf = new NF;
    parse_args(argc,argv);
    for(int i=1;i<core_num;i++){
        std::thread a(thread_main,i);
        a.detach();
    }
    thread_main(0);
}

