#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "hypr_ipc.hpp"
#include "../vmmain.hpp"

namespace superv::loader {
	bool write_elf_file(mapped_view* shbuf, const char* filepath) {
		FILE* f = fopen(filepath, "rb");
		if (!f) {
			printf("[-] Failed to open file: %s\n", filepath);
			destroy_mapped_view(&shbuf);
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

		fread((uint8_t*)(shbuf->view + sizeof(mapped_view)), 1, fsize, f);
		fclose(f);

		shbuf->size = fsize;
		shbuf->ipc.signal = 0;
		shbuf->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		return true;
	}
}
#endif // HYPRLOAD_HPP
