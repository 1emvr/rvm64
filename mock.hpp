#ifndef MOCK_H
#define MOCK_H
#include <windows.h>
#include <string.h>
#include <stdint.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"

#define SHMEM_NAME L"Local\\VMSharedBuffer"

namespace rvm64::mock {
	_native void cache_file(shared_buffer *data) {
		// only for mock-up
	};

	_native void destroy_file(shared_buffer *buffer) {
		if (!buffer) {
			return;
		}
		if (buffer->address) {
			HeapFree(GetProcessHeap(), 0, buffer->address);
			buffer->address = nullptr;
			buffer->size = 0;
		}

		HeapFree(GetProcessHeap(), 0, buffer);
	}

	_native shared_buffer* read_shared_memory() {
		auto data = (shared_buffer*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(shared_buffer));
		if (!data) {
			CSR_SET_TRAP(nullptr, image_bad_load, GetLastError(), 0, 1);
		}

		HANDLE h_map = OpenFileMappingW(FILE_MAP_READ, FALSE, SHMEM_NAME);
		if (!h_map) {
			CSR_SET_TRAP(nullptr, image_bad_load, GetLastError(), 0, 1);
		}

		LPVOID view = MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
		if (!view) {
			CloseHandle(h_map);
			CSR_SET_TRAP(nullptr, image_bad_load, GetLastError(), 0, 1);
		}

		typedef struct {
			size_t size;
			uint8_t payload[1];
		} shared_payload;

		auto shared = (shared_payload*)view;
		if (shared->size == 0) {
			UnmapViewOfFile(view);
			CloseHandle(h_map);
			CSR_SET_TRAP(nullptr, image_bad_load, ERROR_INVALID_DATA, 0, 1);
		}

		return data;
	}
};
#endif // MOCK_H
