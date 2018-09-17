/*
 * ips.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef WAF_CUH
#define WAF_CUH

#include <stdint.h>

#include "picohttpparser.cuh"
#include "reg_match.cuh"

//#define REG_EXPR_NUM 20
//static __device__ char *reg_expr1 = "1+2+3";
//static __device__ char *reg_expr2 = "w+t+f";
//static __device__ char *reg_expr3 = "4+5+6";
//static __device__ char *reg_expr4 = "H+a+H";

#define REG_EXPR_NUM 100
__device__ char *reg_expr_array[REG_EXPR_NUM] = {"pageXOffset","encodeURI","encodeURIComponent","1+2+3", "w+t+f", "4+5+6", "H+a+H","outerHeight","setInterval","decodeURIComponent",
                                      "offscreenBuffering","innerWidth","pageYOffset","onmouseup","propertyIsEnum","clearTimeout","isPrototypeOf","hasOwnProperty","isPrototypeOf","isFinite",
                                       "shift","export","exit","unset","AllowGroups","AllowTcpForwarding","AllowUsers","AuthorizedKeysFile","Banner","Batchmode",
                                       "BindAddress","CheckHostIP","ChrootDirectory","Cipher","Ciphers","ClearAllForwardings","ClientAliveCountMax","ClientAliveInterval","Compression","CompressionLevel",
                                       "DenyUsers","DisableBanner","EscapeChar","FallBackToRsh","ForwardX11","GatewayPorts","HostbasedAuthentication","HostbasedUsesNameFromPacketOnly","HostKeyAlgorithms","IgnoreIfUnknown",
                                       "IgnoreUserKnownHosts","IdentityFile","LoginGraceTime","LookupClientHostnames","MaxStartups","PAMServiceName","PermitRootLogin","PAMServicePrefix","ProxyCommand","RekeyLimit",
                                       "RemoteForward","RhostsRSAAuthentication","ServerAliveCountMax","ServerAliveInterval","Subsystem","UserKnownHostsFile","X11Forwarding","X11UseLocalHost","XAuthLocation","PASSREQ",
                                       "TIMEOUT","SYSLOG_FAILED_LOGINS","CONSOLE","function","Get-Service","Get-Process","Parameter","Mandatory","set-variable","break",
                                       "continue","elseif","foreach","int","xml","hashtable","switch","$Args","$Error","$PSHome",
                                       "$Home","write-output","Hidden","MemberType","MemberSet","Method","GetHashCode","Collections","Property","string"};

#define MAX_STR_LENGTH 4200

struct waf_flow_state {
    // A pointer to the start of the method string
	// char *method;

	// Size of the method string
    size_t method_len;

    // A pointer to the start of the path string
    // char *path;

    // Size of the path string
    size_t path_len;
    // HTTP minor version
    int minor_version;
    // An array for storing the headers
    struct phr_header headers[4];
    // Total number of the parsed headers
    size_t num_headers;
    // A char array which is used to store a string for matching.
    // Whether we have detected a match for a particular request
    bool is_reg_matched;
};

class WAF {
public:
	void *info_for_gpu;

	// Constructor
	__device__ WAF() {
		info_for_gpu = 0;
	}

	// Deconstructor
	__device__ ~WAF() {
	}

	// State initialization
    __device__ inline void init_automataState(struct waf_flow_state& state){
        state.is_reg_matched=false;
    }

	// WAF entry point
	static __device__ inline void nf_logic(void *pkt, struct waf_flow_state* state, void* info) {
		size_t buf_len = *(size_t*)pkt;
		char* req_buf = reinterpret_cast<char*>(pkt+sizeof(size_t));
		const char* method;
		const char* path;
		int ret;
		char str[MAX_STR_LENGTH];

		// First, parse the HTTP request
		ret = phr_parse_request(req_buf,
							   buf_len,
							   &method,
							   &state->method_len,
							   &path,
							   &state->path_len,
							   &state->minor_version,
							   state->headers,
							   &state->num_headers,
							   0);

		// Remove this assert if it doesn't work.
		//assert(ret == buf_len);

		// Do some post processing for this HTTP request
		// ....

		// Then apply regular expression matching.

		// Make sure that the length of the buffer does not exceed
		// the limit.
		assert(buf_len <= (MAX_STR_LENGTH-1));

		// Copy the request buffer, prepare a string.
		memcpy(str, req_buf, buf_len);
		str[buf_len] = '\0';

		// Start regular expression matching
		//state->is_reg_matched = false;
		
		// Copy the following text to apply regular expression
		// matching for different regular expressions.
		state->is_reg_matched = false;
		for(int i=0; i<REG_EXPR_NUM; i++) {
			int ret = match(reg_expr_array[i], str);
			if(ret) {
				state->is_reg_matched = true;
				break;
			}
		}
	}
};

#endif /* IPS_HH */
