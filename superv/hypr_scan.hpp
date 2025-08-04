#ifndef HYPRSCAN_HPP
#define HYPRSCAN_HPP
#include <windows.h>
#include <vector>

namespace scanner {
	bool data_compare(const uint8_t* data, const uint8_t* pattern, const char* mask) {
		for (; *mask; ++mask, ++data, ++pattern) {
			if (*mask == 'x' && *data != *pattern)
				return false;
		}
		return true;
	}

	uintptr_t signature_scan(HANDLE hprocess, uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) {
		std::vector<uint8_t> buffer(size);

		size_t bytes_read = 0;
		size_t pat_length = strlen(mask);

		if (!ReadProcessMemory(hprocess, (LPVOID)base, buffer.data(), size, &bytes_read)) {
			return 0;
		}
		for (size_t i = 0; i <= size - pat_length; ++i) {
			if (data_compare(buffer.data() + i, pattern, mask))
				return base + i;
		}
		return 0;
	}
}
#endif // HYPRSCAN_HPP
