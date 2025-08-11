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
		fclose(f);

		// TODO:
		channel->ipc.signal = 0;
		shbuf->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		return true; 
	}

	vm_channel* get_vm_channel(win_process* proc) {
 		static constexpr char vm_magic[16] = "RMV64_II_BEACON_";

		auto map_offset = superv::scan::signature_scan(proc->handle, proc->base, proc->size, (const uint8_t*)vm_magic, "xxxxxxxxxxxxxxxx");
		if (!map_offset) {
			return nullptr;
		}

		vm_channel *channel = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		if (!channel) {
			return nullptr;
		}

		if (!rvm64::memory::read_process_memory(proc->handle, map_offset, (uint8_t*)channel, sizeof(vm_channel))) {
			return nullptr;
		}
	}
}
#endif // HYPRLOAD_HPP
