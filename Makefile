CFLAGS := -g -O0 -fsanitize=address
#CFLAGS := -O3

main.o: main.c Makefile
	cc $(CFLAGS) -c -o main.o main.c

sha256.o: sha256.c Makefile
	cc $(CFLAGS) -c -o sha256.o sha256.c

block-hash: main.o sha256.o Makefile
	cc $(CFLAGS) main.o sha256.o -o block-hash
