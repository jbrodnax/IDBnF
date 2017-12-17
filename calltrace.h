#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef CALLTRACE_H
#define CALLTRACE_H
#endif

/*ftable offsets and sizes*/
#define MAGICNUM	0x234
#define MAGICPLT	0x567
#define FRST_FN		10
//#define NEXT_FN		45
#define FN_HDR_SIZE	45
#define FN_NAME		32
#define FN_ADDR		8
#define FN_SIZE		4

typedef struct _node_fn{
	struct _fn_entry *fn;
	struct _node_fn *next;
	struct _node_fn *prev;
}node_fn;

struct __attribute__((packed)) _fn_plt{
/*got_addr and plt_addr hold the addrs of the got and plt entries.
* _fn_entry->addr will be updated when plt entry is resolved at runtime.*/
	uint64_t got_addr;
	uint64_t plt_addr;
};

struct __attribute__((packed)) _fn_entry{
	char name[32];
	uint64_t addr;
	uint32_t size;
	void *data;
	struct _fn_plt *fn_plt;
};

struct _fn_mgr{
	node_fn *head;
	node_fn *tail;
	uint32_t list_size;
};

pthread_rwlock_t fn_lock1;
pthread_rwlock_t fn_lock2;

/*Function prototypes*/
void *malloc_s(size_t s);

/*disas prototypes*/
int da_disas_x86(void *data, uint64_t addr, size_t sz);
int da_disas_fn(struct _fn_entry *f);

/*node_fn list prototypes*/
node_fn *nfn_add(struct _fn_entry *fn, struct _fn_mgr *mgr);
node_fn *nfn_search(uint64_t addr, char *name, struct _fn_mgr *mgr);
int nfn_remove(node_fn *node, struct _fn_mgr *mgr);
void nfn_display_fn(node_fn *node, pthread_rwlock_t *lock);
