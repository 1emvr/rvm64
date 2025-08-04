#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

// TODO: separate scopes and create shmem/ipc namespace
namespace superv::loader {
	typedef struct {
		HANDLE 			map;
		LPVOID 			view;
		PBYTE 			buffer;
		SIZE_T 			size;
		volatile int 	signal;
		volatile int 	ready;
	} mapped_view;


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

	// TODO: refactor this and separeate mapped view RW from file loading
	bool write_mapped_view(mapped_view* shbuf, const char* filepath) {
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
			destroy_mapped_view(&shbuf);
			return false;
		}

		uint8_t* data = (uint8_t*)(shbuf->view + sizeof(mapped_view)); // right after the mapped_view struct
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
