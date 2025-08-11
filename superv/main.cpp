#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "supr_load.hpp"
#include "supr_patch.hpp"
#include "supr_scan.hpp"

#include "../include/vmmain.hpp"
#include "../include/vmproc.hpp"

namespace superv {
	void print_usage() {
		printf("usage: superv --process <vm> --elf <riscv_elf>\n");
	}

	int superv_main(const char* proc_name, const char* elf_name) {
		win_process *proc = rvm64::process::get_process_info(proc_name);
		if (!proc) {
			printf("[ERR] Could not find process information for target\n");
			return 1;
		}

		vm_channel* channel = superv::loader::get_vm_channel(proc);
		if (!channel) {
			printf("[ERR] Could not load vm channel\n");
			return 1;
		}

		if (!superv::patch::install_entry_hook(proc, channel)) {
			printf("[ERR] Could not install entrypoint hook in the vm\n");
			return 1;
		}

		if (!superv::patch::install_decoder_hook(proc, channel)) {
			printf("[ERR] Could not install decoder hook in the vm\n");
			return 1;
		}

		if (!superv::loader::write_elf_file(proc->handle, channel, elf_name)) {
			printf("[ERR] Could not load elf to the vm channel\n");
			return 1;
		}

		printf("vm should be starting now..\n");
		// superv::start(vmcs);
		
		return 0;
	}
}

int main(int argc, char** argv) {
		const char *proc_name = nullptr;
		const char *elf_name = nullptr;

		if (argc < 5) {
			print_usage();
			return 1;
		}
		for (int i = 0; i < argc; i++) {
			if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--process") == 0) {
				proc_name = argv[i + 1];
			}
			if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--elf") == 0) {
				elf_name = argv[i + 1];
			}
		}

		if (!proc_name || !elf_name) {
			print_usage();
			return 1;
		}

		return superv::superv_main(proc_name, elf_name);
}
