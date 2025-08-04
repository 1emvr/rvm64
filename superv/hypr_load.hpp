#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

namespace superv::loader {
	typedef struct {
		HANDLE map;
		void* view;
		uint8_t* buffer;
		size_t size;
		volatile int ready;
	} shared_buffer;


	shared_buffer* create_shared_buffer() {
		HANDLE hmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(shared_buffer) + 0x100000, SHMEM_NAME);
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

		auto shbuf = (shared_buffer*)HeapAlloc(GetProcessHeap(), 0, sizeof(shared_buffer));
		shbuf->map = hmap;
		shbuf->view = view;
		return shbuf;
	}

	void destroy_shared_buffer(shared_buffer** shbuf) {
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

	bool write_shared_buffer(shared_buffer* shbuf, const char* filepath) {
		FILE* f = fopen(filepath, "rb");
		if (!f) {
			printf("[-] Failed to open file: %s\n", filepath);
			UnmapViewOfFile(view);
			CloseHandle(hmap);
			return false;
		}

		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize > 0x100000) {
			printf("[-] ELF too large\n");
			fclose(f);
			destroy_shared_buffer(&shbuf);
			return false;
		}

		uint8_t* data = (uint8_t*)(shbuf->view + sizeof(shared_buffer)); // right after the shared_buffer struct
		fread(data, 1, fsize, f);
		fclose(f);

		shbuf->buffer = data;  // VM will memcpy this out
		shbuf->size = fsize;
		shbuf->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		printf("[*] Press ENTER to exit and release shared memory...\n");

		getchar();
		return true;
	}
}
#endif // HYPRLOAD_HPP
