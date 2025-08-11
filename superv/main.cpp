#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "hypr_ipc.hpp"
#include "hypr_load.hpp"
#include "hypr_proc.hpp"
#include "hypr_patch.hpp"

#include "../vm/vmmain.hpp"

namespace superv {
	int superv_main(std::wstring proc_name, char* elf_name) {
		process_t *proc = superv::process::information::get_process_info(proc_name);
		if (!proc) {
			return 1;
		}
		if (!superv::patch::install_entry_hook(proc, shbuf)) {
			return 1;
		}
		if (!superv::patch::install_decoder_hook(proc, shbuf)) {
			return 1;
		}
		if (!superv::loader::write_elf_file(shbuf, elf_name)) {
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

		char *elf_name = argv[0];
		std::wstring proc_name = "rvm64";

		return superv::superv_main(proc_name, elf_name);
}
