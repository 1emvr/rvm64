#include <string.h>
#include <stdlib.h>
#define ebreak()  asm volatile("ebreak")

// NOTE: do not mangle "main"
extern "C" int main() {
	constexpr int result = 0xFFFF;

	void *buffer = malloc(sizeof(int));
	memset(buffer, 0, sizeof(int));

	memcpy(buffer, &result, sizeof(int));
	ebreak();

	void (*fn)() = (void(*)())buffer;
	fn();

	free(buffer);

	return 0;
}
