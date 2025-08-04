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
		HANDLE h_map = OpenFileMappingW(FILE_MAP_READ, FALSE, SHMEM_NAME);
		if (!h_map) {
			return nullptr;
		}

		LPVOID view = MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
		if (!view) {
			CloseHandle(h_map);
			return nullptr;
		}
	
		shared_buffer *remote = (shared_buffer*)view;
		if (!remote->ready) {
			UnmapViewOfFile(view);
			CloseHandle(h_map);
			return nullptr;
		}

		auto packet = (shared_buffer*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(shared_buffer));
		if (!packet) {
			UnmapViewOfFile(view);
			CloseHandle(h_map);
			return nullptr;
		}

		packet->size = remote->size;
		packet->address = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packet->size);

		if (!packet->address) {
			HeapFree(GetProcessHeap(), 0, packet);
			UnmapViewOfFile(view);
			CloseHandle(h_map);
			return nullptr;
		}

		memcpy(packet->address, remote->address, packet->size);

		UnmapViewOfFile(view);
		CloseHandle(h_map);

		return packet;
	}
};
#endif // MOCK_H
