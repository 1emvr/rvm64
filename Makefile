CLG=/usr/bin/clang++
CXX=/usr/bin/x86_64-w64-mingw32-g++

CFLAGS= -O0 -static-libgcc -static-libstdc++ 
EFLAGS= --target=riscv64 -march=rv64g -ffreestanding -nostdlib -fuse-ld=lld \
	-isystem /usr/local/musl/include -Wl,-shared -Wl,-e,main -fPIC

all:
	${CXX} ${CFLAGS} -DDKEY=0 ./vm/vmctx.S -I./vm -c -o ./build/vmctx.o
	${CXX} ${CFLAGS} -DDKEY=0 ./vm/main.cpp ./build/vmctx.o -I./vm -o ./build/rvm64.exe
	${CXX} ${CFLAGS} ./superv/main.cpp -I./superv -I./include -o ./build/superv.exe
	${CLG} ${EFLAGS} ./test/test.cpp -o ./build/test.elf

clean:
	rm ./build/vmctx.o ./build/rvm64.exe ./build/test.elf ./build/superv.exe
