#ifndef HYPRSCAN_HPP
#define HYPRSCAN_HPP
#include <windows.h>

namespace superv::scanner {
	bool data_compare(const uint8_t* data, const uint8_t* pattern, const char* mask) {
		for (; *mask; ++mask, ++data, ++pattern) {
			if (*mask == 'x' && *data != *pattern)
				return false;
		}
		return true;
	}

	uintptr_t signature_scan(HANDLE hprocess, uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) {
		uint8_t *buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, size);

		size_t bytes_read = 0;
		size_t pat_length = strlen(mask);

		if (!ReadProcessMemory(hprocess, (LPVOID)base, buffer, size, &bytes_read)) {
			return 0;
		}
		for (size_t i = 0; i <= size - pat_length; ++i) {
			if (data_compare(buffer + i, pattern, mask))
				return base + i;
		}

		HeapFree(GetProcessHeap(), 0, buffer);
		return 0;
	}
}
#endif // HYPRSCAN_HPP
