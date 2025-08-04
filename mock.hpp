#ifndef MOCK_H
#define MOCK_H
#include <windows.h>
#include <string.h>
#include <stdint.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"

#define SHMEM_NAME L"Local\\VMSharedBuffer"

namespace rvm64::mock {
	typedef struct {
		HANDLE map;
		void* view;
		uint8_t* buffer;
		size_t size;
		volatile int ready;
	} shared_buffer;

	_native void cache_shared_buffer(shared_buffer *data) {
		// only for mock-up. not currently saving anything.
	};

	_native void destroy_shared_buffer(shared_buffer **shbuf) {
		if (shbuf) {
			if ((*shbuf)->buffer) {
				HeapFree(GetProcessHeap(), 0, (*shbuf)->buffer);
				(*shbuf)->buffer = nullptr;
				(*shbuf)->size = 0;
			}

			if ((*shbuf)->view) UnmapViewOfFile((*shbuf)->view);
			if ((*shbuf)->map) CloseHandle((*shbuf)->map);

			HeapFree(GetProcessHeap(), 0, *shbuf);
			*shbuf = nullptr;
		}
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
	
		// TODO: poll here instead of restarting everything
		shared_buffer *remote = (shared_buffer*)view;
		while (!remote->ready) {
			Sleep(10);
		}

		// NOTE: we could free the remote buffer, possibly
		auto packet = (shared_buffer*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(shared_buffer));
		if (!packet) {
			CloseHandle(h_map);
			UnmapViewOfFile(view);
			return nullptr;
		}

		packet->size = remote->size;
		packet->buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packet->size);

		if (!packet->buffer) {
			CloseHandle(h_map);
			UnmapViewOfFile(view);
			destroy_shared_buffer(&packet);
			return nullptr;
		}

		memcpy(packet->buffer, remote->buffer, packet->size);

		UnmapViewOfFile(view);
		CloseHandle(h_map);

		return packet;
	}
};
#endif // MOCK_H
