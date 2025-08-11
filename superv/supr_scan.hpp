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
		if (!buffer) {
			printf("[ERR] signature_scan: could not allocate a buffer.\n");
			return 0;
		}

		size_t bytes_read = 0;
		uintptr_t offset = 0;

		if (!ReadProcessMemory(hprocess, (LPVOID)base, buffer, size, &bytes_read)) {
			printf("[ERR] signature_scan: could not read process memory: 0x%lx\n", GetLastError());
			return 0;
		}
		for (size_t i = 0; i < size; ++i) {
			if (data_compare(buffer + i, pattern, mask)) {
				offset = base + i;
				break;
			}
		}

		HeapFree(GetProcessHeap(), 0, buffer);
		return offset;
	}
}
#endif // HYPRSCAN_HPP
