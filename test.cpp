#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#define ebreak()  asm volatile("ebreak")

extern "C" int main() {
	void *buffer = mmap(nullptr, 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, 3, 0);
	memset(buffer, 0, 2);

	char code[1024] = { 0xcc, 0xc3 };
	memcpy(buffer, &code, 2);

	void (*fn)() = (void(*)())buffer;
	fn();

	munmap(buffer, 2);
	return 0;
}
