#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP
#include "../vmmain.hpp"

#define MAPPED_VIEW_BUFFER_SIZE 0x100000

namespace ipc {
	mapped_view* create_mapped_view() {
		HANDLE hmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(mapped_view) + MAPPED_VIEW_BUFFER_SIZE, SHMEM_NAME); 
		if (!hmap) {
			printf("[-] CreateFileMappingW failed: %lu\n", GetLastError());
			return nullptr;
		}

		LPVOID address = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
		if (!view) {
			printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
			CloseHandle(hmap);
			return nullptr;
		}

		auto shbuf = (mapped_view*)HeapAlloc(GetProcessHeap(), 0, sizeof(mapped_view));
		shbuf->buffer.address = (uintptr_t)address;
		shbuf->map = hmap;

		return shbuf;
	}

	void destroy_mapped_view(mapped_view** shbuf) {
		if (!shbuf || !(*shbuf)->buffer.address) {
			return;
		}

		UnmapViewOfFile((void*)(*shbuf)->buffer.address);
		if ((*shbuf)->map) {
			CloseHandle((*shbuf)->map);
		}

		HeapFree(GetProcessHeap(), 0, (*shbuf));
		*shbuf = nullptr;
	}

	bool read_mapped_view(mapped_view* shbuf, uint8_t* data, uintptr_t offset, size_t size) {
		if (!shbuf || !data) {
			return false;
		}
		if (offset > MAPPED_VIEW_BUFFER_SIZE || size > MAPPED_VIEW_BUFFER_SIZE - offset) {
			return false;
		}

		memcpy(data, (uint8_t*)(shbuf->buffer.address + offset), size);
		return true;
	}

	bool write_mapped_view(mapped_view* shbuf, const uint8_t* data, uintptr_t offset, size_t size) {
		if (!shbuf || !data) {
			return false;
		}
		if (offset > MAPPED_VIEW_BUFFER_SIZE || size > MAPPED_VIEW_BUFFER_SIZE - offset) {
			return false;
		}

		memcpy((uint8_t*)(shbuf->buffer.address + offset), data, size);
		return true;
	}
}
#endif // HYPRIPC_HPP
