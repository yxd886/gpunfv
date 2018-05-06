#ifndef FIREWALL_HH
#define FIREWALL_HH

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cassert>

//#include "../include/vector.hh"

#include "../include/packet_parser.hh"
#include "../include/gpu_interface.hh"

using namespace std;

#define MAX_RULES	10000000	// Maximum rule amount
#define NRULES		1000		// Rule amount

//void *gpu_init(unsigned size, void *ptr);

struct Rule{
	uint32_t saddr;			// source ip address (network byte order)
	uint32_t daddr;			// destination ip address (network byte order)
	uint32_t smask;			// source network mask (host byte order)
	uint32_t dmask;			// destination network mask (host byte order)
	uint16_t sport, dport;  // source port, destination port
	uint8_t protocol;		// protocol type
	enum {PASS, DROP};		// action id
	uint8_t action;			// action
};

class firewall_flow_state {
public:
	//time_t createdTime;
	//time_t refreshTime;
	int match_no;
	int drop_no;
	int pass_no;
	bool current_pass;
	int counter;
};

class Firewall {
	vector<Rule> rules;
public:
	void *info_for_gpu;

	Firewall() : info_for_gpu(0) {
		uint32_t n = NRULES;
		assert(n > 0 && n < MAX_RULES);
		Rule rule;
		for(uint32_t i = 0; i < n; i++) {
			rule.saddr = i2ip((i >> 24) % 256, (i >> 16) % 256, (i >> 8) % 256, i % 256);		// source ip 0~n
			rule.daddr = i2ip(10, 10, 0, 2);		// destination ip 10.10.0.2
			rule.smask = i2ip(255, 255, 255, 255);	// source mask 255.255.255.255
			rule.dmask = i2ip(255, 255, 255, 255);	// destination mask 255.255.255.255
			rule.sport = net::myhtons(0xaabb);					// source port 
			rule.dport = net::myhtons(0xccdd);					// destination port
			rule.protocol = packetInfo::UDP;
			rule.action = Rule::DROP;
			rules.push_back(rule);
		}

		nf_init();
	}

	inline void nf_init() {
		assert(rules.size());

		info_for_gpu = init_nf_info(rules.size(), &rules[0]);
	}

	// Convert 4 integers to a network byte order ip address
	inline uint32_t i2ip(uint8_t s0, uint8_t s1, uint8_t s2, uint8_t s3) {
		uint32_t res;
		uint8_t *p = (uint8_t *) &res;

		*(p + 0) = s0;
		p[1] = s1;
		p[2] = s2;
		p[3] = s3;

		return res;
	}

	inline void init_automataState(firewall_flow_state &state) {
		state.match_no = 0;
		state.drop_no = 0;
		state.pass_no = 0;
		state.current_pass = 0;
		state.counter = 0;
	}

	inline void nf_logic(void *pkt, firewall_flow_state *state) {	// specify nf logic function
	    process(pkt, state);
	}

private:
	inline void process(void *packet, firewall_flow_state* state) {
		packetInfo info;
		rte_prefetch0((void*)packet);
		rte_prefetch0((void*)&rules[0]);
		packetParser::parse_raw_packet(packet, &info);
		match_rules(&info, state);
	}

	inline bool ip_eq_mask(uint32_t addr1, uint32_t addr2, uint32_t mask) {
		return (net::myntohl(addr1) & mask) == (net::myntohl(addr2) & mask);
	}

	void match_rules(packetInfo *info, firewall_flow_state* state) {
		uint32_t s_addr, d_addr;
		uint16_t s_port, d_port;
		uint8_t protocol;

		s_addr = info->_ipv4_hdr->src_addr;
		d_addr = info->_ipv4_hdr->dst_addr;
		protocol = info->_protocol;

		if(protocol == packetInfo::TCP) {
			s_port = info->_tcp_hdr->src_port;
			d_port = info->_tcp_hdr->dst_port;
		}
		else if(protocol == packetInfo::UDP) {
			s_port = info->_udp_hdr->src_port;
			d_port = info->_udp_hdr->dst_port;
		}
		else {
			assert(0 && "Unsupported protocol.");
		}
		
		state->counter++;

		bool drop;
		uint32_t i;




		// Match rules
		for(i = 0; i < rules.size(); i++){
			Rule temp = rules[i];	// GPU vector access must via this copy

			if(temp.saddr == ANY_ADDR ? false : 
					!ip_eq_mask(temp.saddr, s_addr, temp.smask))
				continue;

			if(temp.daddr == ANY_ADDR ? false : 
					!ip_eq_mask(temp.daddr, d_addr, temp.dmask))
				continue;

			if(temp.protocol == ANY_PROTOCOL ? false : !(temp.protocol == protocol))
				continue;

			if(temp.sport == ANY_PORT ? false : !(temp.sport == s_port))
				continue;
			
			if(temp.dport == ANY_PORT ? false : !(temp.dport == d_port))
				continue;
			
			// Perfect match
			state->match_no++;

			if(temp.action == Rule::PASS)
				drop = false;
			else if(temp.action == Rule::DROP)
				drop = true;
			else
				assert(0 && "Unexpected action id");
			
			break;
		}

		if(i >= rules.size() || drop) { 	// Match nothing or match a rule of drop, drop the packet
			state->drop_no++;
			state->current_pass = false;

			//printf("DROP\n");
		}
		else {
			state->pass_no++;
			state->current_pass = true;

			//printf("PASS\n");
		}
	}

};

#endif /* FIREWALL_HH */
