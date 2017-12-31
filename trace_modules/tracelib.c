#include "../calltrace.h"
/*
struct _trace_proc {
	char *name;
	pid_t pid;
	int status;
	struct user_regs_struct oldregs;
	struct user_regs_struct newregs;
};

struct _trace_proc tproc;


void *malloc_s(size_t s){
	void *p;
	if((p = malloc(s)) == NULL){
		perror("[!] Error in malloc ");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, s);
	return p;
}

int loadfns(char *fname){
	long int fsize;
	int magicnum, numfns;
	uint32_t offset;
	FILE *fp;
	char *input;
	struct _fn_entry *f;

	if(!(fp = fopen(fname, "r"))){
		perror("[!] Error: ");
		exit(EXIT_FAILURE);
	}


	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	if(fsize < 1){
		printf("[!] Error: in loadfuncs. Invalid file size.\n");
		exit(EXIT_FAILURE);
	}

	input = malloc_s(fsize);
	if((fread(input, fsize, 1, fp)) < 1){
		perror("[!] Error: ");
		exit(EXIT_FAILURE);
	}
	fclose(fp);


	memcpy(&magicnum, input, sizeof(int));
	if(magicnum != MAGICNUM){
		printf("[!] Error: in loadfuncs. Invalid file type.\n");
		exit(EXIT_FAILURE);
	}
	memcpy(&numfns, &input[sizeof(int)+1], sizeof(int));
	printf("Number of symbols: %d\n", numfns);


	offset = FRST_FN;
	while(numfns > 0){
		if(offset >= fsize)
			return 0;

		f = malloc_s(sizeof(struct _fn_entry));
		memcpy(f, &input[offset], sizeof(struct _fn_entry));
		offset+=FN_HDR_SIZE;

		f->data = malloc_s(f->size);
		memcpy(f->data, &input[offset], f->size);
		//nfn_add(f, &fn_mgr);
		ll_add(f, &fn_mgr);
		offset+=f->size+1;
		numfns--;
	}


	memcpy(&magicnum, &input[offset], sizeof(int));
	if(magicnum != MAGICPLT){
		printf("[!] Error: in loadfuncs. Invalid plt id.\n");
		exit(EXIT_FAILURE);
	}

	offset+=(sizeof(int)+1);
	while(offset < fsize){
		f = malloc_s(sizeof(struct _fn_entry));
		memcpy(f, &input[offset], (FN_NAME+FN_ADDR));
		f->fn_plt = malloc_s(sizeof(struct _fn_plt));
		f->fn_plt->plt_addr = f->addr;
		//nfn_add(f, &fn_mgr);
		ll_add(f, &fn_mgr);
		offset+=(FN_NAME+FN_ADDR)+1;
	}

	return 0;
}
*/
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
/*
int main(int argc, char *argv[]){
	char *filename;
	size_t fl_1, fl_2;

	if(argc != 3){
		printf("Usage: %s <binary file> <function file>\n", argv[0]);
		exit(0);
	}

	fl_1 = strlen(argv[1]);
	if(fl_1 < 1){
		printf("Invalid binary file name.\n");
		exit(1);
	}

	fl_2 = strlen(argv[2]);
	if(fl_2 < 1){
		printf("Invalid function file name.\n");
		exit(1);
	}

	memset(&fn_mgr, 0, sizeof(list_mgr));
	filename = argv[2];
	loadfns(filename);
	nfn_display_all(&fn_mgr);

	memset(&tproc, 0, sizeof(struct _trace_proc));
	tproc.name = malloc_s(fl_1+1);
	strncpy(tproc.name, argv[1], (fl_1+1));
	init_trace(&tproc);

	ll_clean(&fn_mgr);
	
	return 0;
}
*/


