#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#define __debugbreak()  asm volatile("ebreak")

extern "C" int main() {
	char code[] = { 0xcc,0x55,0x48,0x89,0xe5,0x90,0x5d,0xc3,0xcc };

	size_t size = sizeof(code);
	void *buffer = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, 3, 0);

	__debugbreak();
	if (buffer == nullptr) {
		exit(1);
	}

	memset(buffer, 0, size);
	memcpy(buffer, &code, size);

	void (*fn)() = (void(*)())buffer;
	fn();

	munmap(buffer, sizeof(code));
	return 0;
}
