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

static const char *reg_expr1 = "";
static const char *reg_expr2 = "";
static const char *reg_expr3 = "";
static const char *reg_expr4 = "";

static const char *reg_expr_array[REG_EXPR_NUM] = {reg_expr1, reg_expr2, reg_expr3, reg_expr4};

struct waf_flow_state {
    // A pointer to the start of the method string
	char *method;
	// Size of the method string
    size_t method_len;
    // A pointer to the start of the path string
    char *path;
    // Size of the path string
    size_t path_len;
    // HTTP minor version
    int minor_version;
    // An array for storing the headers
    struct phr_header headers[4];
    // Total number of the parsed headers
    size_t num_headers;
    // Whether we have detected a match for a particular request
    bool is_reg_matched;
};

class WAF {
public:

	// Constructor
	WAF() {
	}

	// Deconstructor
	~WAF() {
	}

	// WAF entry point
	inline void nf_logic(void *pkt, struct waf_flow_state* state) {

	}
};

#endif /* IPS_HH */
