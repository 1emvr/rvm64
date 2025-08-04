#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "hypr_ipc.hpp"
#include "hypr_load.hpp"
#include "hypr_proc.hpp"
#include "hypr_patch.hpp"

#include "../vmmain.hpp"

namespace superv {
	int main(int argc, char** argv) {
		if (argc < 2) {
			printf("Usage: %s <riscv_elf_file>\n", argv[0]);
			return 1;
		}

		std::wstring target_name = "rvm64";
		process_t *proc = superv::process::information::get_process_info(target_name);
		if (!proc) {
			return 1;
		}

		mapped_view *shbuf = superv::ipc::create_mapped_view();
		if (!shbuf) {
			return 1;
		}
		if (!superv::patch::install_entry_hook(proc, shbuf)) {
			return 1;
		}
		if (!superv::patch::install_decoder_hook(proc, shbuf)) {
			return 1;
		}
		if (!superv::loader::write_elf_file(shbuf, argv[1])) {
			return 1;
		}

		printf("VM Should be starting now..\n");
		/*
		TODO: IPC/Decoder loop
		 while (true) { 
		 	break;
		}
		*/
		
		superv::ipc::destroy_mapped_view(&shbuf);

		return 0;
	}
}
