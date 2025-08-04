#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

namespace ipc {
	mapped_view* create_mapped_view() {
		HANDLE hmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(mapped_view) + 0x100000, SHMEM_NAME);
		if (!hmap) {
			printf("[-] CreateFileMappingW failed: %lu\n", GetLastError());
			return nullptr;
		}

		LPVOID view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
		if (!view) {
			printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
			CloseHandle(hmap);
			return nullptr;
		}

		auto shbuf = (mapped_view*)HeapAlloc(GetProcessHeap(), 0, sizeof(mapped_view));
		shbuf->map = hmap;
		shbuf->view = view;
		return shbuf;
	}

	void read_mapped_view(mapped_view* shbuf) {

	}

	void write_mapped_view(mapped_view* shbuf) {

	}

	void destroy_mapped_view(mapped_view** shbuf) {
		if (*shbuf) {
			if ((*shbuf)->view) {
				UnmapViewOfFile((*shbuf)->view);
			}
			if ((*shbuf)->map) {
				CloseHandle((*shbuf)->map);
			}
			HeapFree(GetProcessHeap(), 0, (*shbuf));
			*shbuf = nullptr;
		}
	}
}
#endif // HYPRIPC_HPP
