#pragma once
#include <windows.h>

namespace superv::loader {
	bool write_shared_buffer(const char* filepath) {
		HANDLE hmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(shared_buffer) + 0x100000, SHMEM_NAME);
		if (!hmap) {
			printf("[-] CreateFileMappingW failed: %lu\n", GetLastError());
			return false;
		}

		LPVOID view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
		if (!view) {
			printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
			CloseHandle(hmap);
			return false;
		}

		shared_buffer* shbuf = (shared_buffer*)view;

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
			UnmapViewOfFile(view);
			CloseHandle(hmap);
			return false;
		}

		uint8_t* data = (uint8_t*)(shbuf + 1); // right after the shared_buffer struct
		fread(data, 1, fsize, f);
		fclose(f);

		shbuf->address = data;  // VM will memcpy this out
		shbuf->size = fsize;
		shbuf->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		printf("[*] Press ENTER to exit and release shared memory...\n");
		getchar();

		UnmapViewOfFile(view);
		CloseHandle(hmap);
		return true;
	}
}
