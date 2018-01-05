#include "../calltrace.h"

struct _trace_proc {
	char *name;
	pid_t pid;
	int status;
	struct user_regs_struct oldregs;
	struct user_regs_struct newregs;
};
