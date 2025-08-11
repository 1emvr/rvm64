#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "hypr_ipc.hpp"
#include "../vmmain.hpp"

namespace superv::loader {
	bool write_elf_file(vm_channel* channel, const char* filepath) {
		FILE* f = fopen(filepath, "rb");
		if (!f) {
			printf("[-] Failed to open file: %s\n", filepath);
			return false;
		}

		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize > 0x100000) {
			printf("[-] ELF too large\n");
			fclose(f);
			return false;
		}

		fread((uint8_t*)channel->view.buffer, 1, fsize, f);
		channel->view.write_size = fsize;
		fclose(f);

		// TODO:
		channel->ipc.signal = 1; // 1 = image load
		channel->ipc.ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		return true; 
	}
}
#endif // HYPRLOAD_HPP
