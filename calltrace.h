#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <limits.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

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

#define LTYPE_FNE	1
#define LTYPE_PLT	2

#define MAX_SUBROUTINES	15

typedef struct _node_fn{
	void *fn;
	struct _node_fn *next;
	struct _node_fn *prev;
}node_fn;

typedef struct _list_manager{
	pthread_rwlock_t ll_lock;
	node_fn *head;
	node_fn *tail;
	uint32_t list_size;
	uint8_t type;
}list_mgr;

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
	struct _fn_entry **subroutines;
	uint16_t num_subroutines;
};

struct _trace_proc {
	char *name;
	pid_t pid;
	int status;
	struct user_regs_struct oldregs;
	struct user_regs_struct newregs;
};

//pthread_rwlock_t fn_lock1;
pthread_rwlock_t fn_lock2;

/*Function prototypes*/
void *malloc_s(size_t s);

/*disas prototypes*/
int da_init_platform(char *arch, uint8_t da_flavor);
void da_destroy_platform();
int da_disas_x86(void *data, uint64_t addr, size_t sz);
int da_disas_fn(struct _fn_entry *f);
uint64_t* da_link_subroutines(node_fn *node, list_mgr *lmgr);

/*list_ops prototypes*/
list_mgr *ll_init_manager();
int ll_destroy(list_mgr *mgr);
node_fn *ll_add(void *data, list_mgr *mgr);
int ll_remove(node_fn *node, list_mgr *mgr);
int ll_clean(list_mgr *mgr);

/*node_fn list prototypes*/
node_fn *nfn_search(uint64_t addr, char *name, list_mgr *mgr);
node_fn * nfn_plt_search(uint64_t call_addr, list_mgr *mgr);
void nfn_display_all(list_mgr *mgr);
void nfn_display(node_fn *node, pthread_rwlock_t *lock);
void nfn_subroutines(list_mgr *mgr);
void nfn_subroutines_display(struct _fn_entry *entry_pt, uint8_t lvl, list_mgr *mgr);

/*trace lib prototypes*/
int init_calltraps(struct _trace_proc *tproc);
void calltrace(struct _trace_proc *tproc);
int init_trace(struct _trace_proc *tproc);


