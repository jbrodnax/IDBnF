#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void func1(int i){
	printf("%d\n", i+1);
	return;
}

int main(){
	int i = 0;

	func1(i);	
	return 0;
}
