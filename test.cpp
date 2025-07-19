#include <string.h>
#include <stdlib.h>
#define ebreak()  asm volatile("ebreak")

// NOTE: do not mangle "main"
extern "C" int main() {
	constexpr int result = 0xFFFF;

	ebreak();
	void *buffer = malloc(sizeof(int));

	ebreak();
	memcpy(buffer, &result, sizeof(int));
	ebreak();
	memset(buffer, 0, sizeof(int));
	ebreak();
	free(buffer);

	return 0;
}
