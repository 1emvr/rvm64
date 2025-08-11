#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "supr_ipc.hpp"
#include "supr_load.hpp"
#include "supr_proc.hpp"
#include "supr_patch.hpp"

#include "../vmmain.hpp"

namespace superv {
	int superv_main(char* proc_name, char* elf_name) {
		std::wstring wproc = proc_name;
		std::wstring sproc = "superv";

		win_process *superv = rvm64::process::information::get_process_info(sproc);
		if (!superv) {
			return 1;
		}
		win_process *proc = superv::process::information::get_process_info(wproc);
		if (!proc) {
			return 1;
		}
		auto channel = rvm64::ipc::load_vm_channel(proc);
		if (!channel) {
			printf("[ERR] Could not map the vm channel\n");
			return 1;
		}
		if (!superv::patch::install_entry_hook(proc)) {
			printf("[ERR] Could not install entrypoint hook in the vm\n");
			return 1;
		}
		if (!superv::patch::install_decoder_hook(proc)) {
			printf("[ERR] Could not install decoder hook in the vm\n");
			return 1;
		}
		if (!superv::loader::write_elf_file(elf_name)) {
			printf("[ERR] Could not load the elf to the vm channel\n");
			return 1;
		}

		printf("vm should be starting now..\n");
		return 0;
	}
}

int main(int argc, char** argv) {
		if (argc < 2) {
			printf("usage: %s <riscv_elf_file>\n", argv[0]);
			return 1;
		}

		return superv::superv_main("rvm64", argv[0]);
}
