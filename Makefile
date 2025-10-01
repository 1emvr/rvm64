CLG=/usr/bin/clang++
CXX=/usr/bin/x86_64-w64-mingw32-g++ 
LLD=/usr/bin/ld.lld

CFLAGS= -O0 -static-libgcc -static-libstdc++ 
EFLAGS= --target=riscv64 -march=rv64g 		\
		-fPIC -ffreestanding -fno-builtin 	\
		-I /usr/local/musl/include 			

LDFLAGS= -shared --allow-shlib-undefined --hash-style=gnu --eh-frame-hdr

all:
	${CXX} ${CFLAGS} -DDKEY=0 ./vm/vmctx.S -I./vm -c -o ./build/vmctx.o
	${CXX} ${CFLAGS} -DDKEY=0 ./vm/main.cpp ./build/vmctx.o -I./vm -o ./build/rvm64.exe
	${CLG} ${EFLAGS} -c ./test/test.cpp -o ./build/test.o
	${LLD} ${LDFLAGS} ./build/test.o -o ./build/test.elf 	

clean:
	rm -f ./build/vmctx.o ./build/rvm64.exe ./build/test.o ./build/test.elf 
