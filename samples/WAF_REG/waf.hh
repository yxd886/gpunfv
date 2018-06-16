/*
 * ips.hh
 *
 *  Created on: Apr 4, 2018
 *      Author: xiaodongyi
 */

#ifndef WAF_HH
#define WAF_HH

#include <stdint.h>

#include "picohttpparser.hh"
#include "reg_match.hh"

#define REG_EXPR_NUM 4
static char *reg_expr1 = "1+2+3";
static char *reg_expr2 = "w+t+f";
static char *reg_expr3 = "4+5+6";
static char *reg_expr4 = "H+a+H";
static char *reg_expr_array[REG_EXPR_NUM] = {reg_expr1, reg_expr2, reg_expr3, reg_expr4};

#define MAX_STR_LENGTH 65535

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
    char str[MAX_STR_LENGTH];
    // Whether we have detected a match for a particular request
    bool is_reg_matched;
};

class WAF {
public:
	void *info_for_gpu;

	// Constructor
	WAF() {
		info_for_gpu = nullptr;
	}

	// Deconstructor
	~WAF() {
	}

	// State initialization
    inline void init_automataState(struct waf_flow_state& state){
        state.is_reg_matched=false;
    }

	// WAF entry point
	inline void nf_logic(void *pkt, struct waf_flow_state* state) {
		size_t buf_len = *(size_t*)pkt;
		char* req_buf = reinterpret_cast<char*>(pkt+sizeof(size_t));
		const char* method;
		const char* path;

		// First, parse the HTTP request
		int ret = phr_parse_request(req_buf,
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
		assert(ret == buf_len);

		// Do some post processing for this HTTP request
		// ....

		// Then apply regular expression matching.

		// Make sure that the length of the buffer does not exceed
		// the limit.
		assert(buf_len <= (MAX_STR_LENGTH-1));

		// Copy the request buffer, prepare a string.
		memcpy(state->str, req_buf, buf_len);
		state->str[buf_len] = '\0';

		// Start regular expression matching
		state->is_reg_matched = false;
		for(int i=0; i<REG_EXPR_NUM; i++) {
			int ret = match(reg_expr_array[i], state->str);
			if(ret) {
				state->is_reg_matched = true;
				break;
			}
		}

	}
};

#endif /* IPS_HH */
