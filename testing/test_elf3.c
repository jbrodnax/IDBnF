#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char func3(char c){
	return c+1;
}

int func2(int i){
	int c1;

	c1 = func3((char)i);
	return (int)c1;
}
void func1(int i){
	int x = func2(i);
	printf("func2 ret: (int) %d\n", x);
	char c = func3((char)x);
	printf("func3 ret: (char) %c\n", c);
	return;
}

int main(){
	int i = 65;

	func1(i);
	func2(i);
	return 0;
}
