#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define SHMEM_NAME L"Local\\VMSharedBuffer"

typedef struct {
    uint8_t* address;
    size_t size;
    volatile int ready;
} shared_buffer;

namespace loader {
	bool write_shared_buffer(const char* filepath) {
		HANDLE h_map = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(shared_buffer) + 0x100000, SHMEM_NAME);
		if (!h_map) {
			printf("[-] CreateFileMappingW failed: %lu\n", GetLastError());
			return false;
		}

		LPVOID view = MapViewOfFile(h_map, FILE_MAP_WRITE, 0, 0, 0);
		if (!view) {
			printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
			CloseHandle(h_map);
			return false;
		}

		shared_buffer* shbuf = (shared_buffer*)view;

		FILE* f = fopen(filepath, "rb");
		if (!f) {
			printf("[-] Failed to open file: %s\n", filepath);
			UnmapViewOfFile(view);
			CloseHandle(h_map);
			return false;
		}

		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize > 0x100000) {
			printf("[-] ELF too large\n");
			fclose(f);
			UnmapViewOfFile(view);
			CloseHandle(h_map);
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
		CloseHandle(h_map);
		return true;
	}
}

int main(int argc, char** argv) {
	// TODO: main loop 
    if (argc < 2) {
        printf("Usage: %s <riscv_elf_file>\n", argv[0]);
        return 1;
    }

    if (!write_shared_buffer(argv[1])) {
        return 1;
    }

	printf("VM Should be starting now..\n");
    return 0;
}
