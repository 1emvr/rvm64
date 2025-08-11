#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "supr_ipc.hpp"
#include "supr_load.hpp"
#include "supr_proc.hpp"
#include "supr_patch.hpp"

#include "../vmmain.hpp"

namespace superv {
	int superv_main(const char* proc_name, const char* elf_name) {
		std::wstring wproc = proc_name;

		win_process *proc = superv::process::information::get_process_info(wproc);
		if (!proc) {
			printf("[ERR] Could not find process information for target\n");
			return 1;
		}
		vm_channel *channel = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		if (!channel) {
			printf("[ERR] Could not create the vm channel\n");
			return 1;
		}

 		static constexpr char vm_magic[16] = "RMV64_II_BEACON_";
		auto chan_offset = superv::scan::signature_scan(proc->handle, proc->base, proc->size, (const uint8_t*)vm_magic, "xxxxxxxxxxxxxxxx");

		if (!chan_offset) {
			printf("[ERR] Could not find the vm channel\n");
			return 1;
		}
		if (!rvm64::memory::read_process_memory(proc->handle, chan_offset, (uint8_t*)channel, sizeof(vm_channel))) {
			printf("[ERR] Could not read the vm channel\n");
			return 1;
		}

		// NOTE: channel is now populated with vm data
		vmcs_t *vmcs = (vmcs_t*)channel->ipc.vmcs;
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
