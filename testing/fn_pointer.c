#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct _FN_STRUCT {
	int v1, v2;
	void *self;
	void (*f1)();

}fnstruct_t;

fnstruct_t fn1;
void fn_init(fnstruct_t *fn, int v1, int v2);
void func1();

void fn_init(fnstruct_t *fn, int v1, int v2){
	memset(fn, 0, sizeof(fnstruct_t));
	fn->self = (void *)fn;
	fn->v1 = v1;
	fn->v2 = v2;
	fn->f1 = &func1;
	return;
}

void func1(){
	printf("i is: %d\n", 1);
	return;
}

int main(int argc, char *argv[]){
	fn_init(1, 2);
	fn1.f1();
	fn1.f1();

	return 0;
}
