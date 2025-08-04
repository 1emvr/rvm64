#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "hypr_load.hpp"
#include "hypr_proc.hpp"
#include "hypr_patch.hpp"

#define SHMEM_NAME L"Local\\VMSharedBuffer"

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

		shared_buffer *shbuf = create_shared_buffer();
		if (!shbuf) {
			return 1;
		}

		if (!superv::patch::install_entry_patch(proc, (uintptr_t)shbuf->view + offsetof(shared_buffer, ready))) {
			return 1;
		}
		/*
			if (!superv::patch::install_step_patch(proc, shbuf->view) {
				return 1;
			}
		*/ 

		if (!write_shared_buffer(shbuf, argv[1])) {
			return 1;
		}

		destroy_shared_buffer(&shbuf);
		printf("VM Should be starting now..\n");

		return 0;
	}
}
