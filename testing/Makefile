LIBNAME=capstone

capstone_test1: capstone_test1.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@
