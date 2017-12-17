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
#define FRST_FN		5
#define NEXT_FN		45
#define FN_NAME		32
#define FN_ADDR		8
#define FN_SIZE		4

typedef struct _node_fn{
	struct _fn_entry *fn;
	struct _node_fn *next;
	struct _node_fn *prev;
}node_fn;

struct __attribute__((packed)) _fn_entry{
	char name[32];
	uint64_t addr;
	uint32_t size;
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

/*function_list prototypes*/
node_fn *nfn_add(struct _fn_entry *fn, struct _fn_mgr *mgr);
node_fn *nfn_search(uint64_t addr, char *name, struct _fn_mgr *mgr);
int nfn_remove(node_fn *node, struct _fn_mgr *mgr);
void nfn_display_fn(node_fn *node, pthread_rwlock_t *lock);
