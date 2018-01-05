#include "../calltrace.h"

int init_calltraps(struct _trace_proc *tproc){

	return 0;
}

void calltrace(struct _trace_proc *tproc){

	if(!tproc)
		return;

	while(1){
		wait(&tproc->status);
		if(WIFEXITED(tproc->status)){
			printf("[*] Child has already exited.\n");
			return;
		}
		printf("[*] Successfully attached to child. Now Continuing.\n");
		ptrace(PTRACE_CONT, tproc->pid, NULL, NULL);
		break;
	}

	return;
}

int init_trace(struct _trace_proc *tproc){

	if(!tproc)
		return -1;

	tproc->pid = fork();
	if(tproc->pid < 0)
		return -1;

	if(tproc->pid == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if(!tproc->name)
			exit(EXIT_FAILURE);
		execve(tproc->name, NULL, NULL);
	}else{
		calltrace(tproc);
	}

	return 0;
}











