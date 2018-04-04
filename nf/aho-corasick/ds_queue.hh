#pragma once
#ifndef AHO_CORASICK_DS_QUEUE_HH
#define AHO_CORASICK_DS_QUEUE_HH


#define DS_QUEUE_DBG 0

#define ds_queue_printf(...) \
	do { \
		if(DS_QUEUE_DBG == 1) { \
			printf(__VA_ARGS__); \
		} \
	} while(0)

struct ds_qnode {
	int data;
	struct ds_qnode *next;
};

struct ds_queue {
	struct ds_qnode *head, *tail;
	int count;
};

#endif
