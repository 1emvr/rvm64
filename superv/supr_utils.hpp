#include <cstdint>
#include <stdio.h>

namespace superv::utils {
	void print_bytes(uint8_t *buffer, size_t size) {
		printf("\n\t");
		for (int i = 0; i < size; i++) {
			std::printf("0x%02" PRIxPTR "%s", (uint8_t)buffer[i], ((i + 1) % 8 == 0) ? "\n\t" : "  ");
		}
		printf("\n\n");
	}
}
