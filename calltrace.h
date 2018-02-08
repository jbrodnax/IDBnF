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

struct __attribute__((packed)) _TR_node {
	struct _fn_entry *fn;
	struct _TR_node *parent;
	uint8_t num_children;
	struct _TR_node **children;
};

typedef struct _tree_manager {
	pthread_rwlock_t tr_lock;
	uint16_t depth;
	struct _TR_node *root;
	struct _TR_node *last_visited;
}treemgr_t;

struct _trace_proc {
	char *name;
	pid_t pid;
	int status;
	struct user_regs_struct oldregs;
	struct user_regs_struct newregs;
};

pthread_rwlock_t fn_lock1;
pthread_rwlock_t fn_lock2;

/*Function prototypes*/
void *malloc_s(size_t s);

/*disas prototypes*/
int da_disas_x86(void *data, uint64_t addr, size_t sz);
int da_disas_fn(struct _fn_entry *f);
struct _fn_entry ** da_link_subroutines(node_fn *node, list_mgr *lmgr);

/*list_ops prototypes*/
node_fn *ll_add(void *data, list_mgr *mgr);
int ll_remove(node_fn *node, list_mgr *mgr);
int ll_clean(list_mgr *mgr);

/*node_fn list prototypes*/
node_fn *nfn_search(uint64_t addr, char *name, list_mgr *mgr);
void nfn_display_all(list_mgr *mgr);
void nfn_display(node_fn *node, pthread_rwlock_t *lock);
void nfn_subroutines(list_mgr *mgr);

/*sa_calltree prototypes
treemgr_t * init_sa_calltree(struct _fn_entry *fn_root);
struct _TR_node *sa_init_TRnode(struct _fn_entry *f, struct _TR_node *parent, treemgr_t *mgr);
int sa_calltree(struct _TR_node *node, list_mgr *lmgr, treemgr_t *mgr);
struct _TR_node *sa_addchild(struct _TR_node *parent, struct _fn_entry *f, treemgr_t *mgr);
void sa_printfn_xrefs(struct _TR_node *c);
*/

/*trace lib prototypes*/
int init_calltraps(struct _trace_proc *tproc);
void calltrace(struct _trace_proc *tproc);
int init_trace(struct _trace_proc *tproc);


