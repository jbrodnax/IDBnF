#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int func2(int i){
	return i+1;
}
void func1(int i){
	int x = func2(i);
	return;
}

int main(){
	int i = 0;

	func1(i);
	func2(i);
	return 0;
}
