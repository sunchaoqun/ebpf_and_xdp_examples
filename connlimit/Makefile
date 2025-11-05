all: main

main.bpf.o: main.bpf.c main.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -c main.bpf.c -o main.bpf.o

main.skel.h: main.bpf.o
	sudo bpftool gen skeleton main.bpf.o > main.skel.h

main: main.skel.h main.c main.h
	gcc -o main main.c -lbpf -Wall

clean:
	rm -f main.bpf.o main.skel.h main

.PHONY: all clean

