#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "supr_load.hpp"
#include "supr_patch.hpp"
#include "supr_scan.hpp"

#include "../include/vmmain.hpp"
#include "../include/vmproc.hpp"

namespace superv {
	int superv_main(const char* proc_name, const char* elf_name) {
		win_process *proc = rvm64::process::get_process_info(proc_name);
		if (!proc) {
			printf("[ERR] Could not find process information for target\n");
			return 1;
		}
		vm_channel *channel = (vm_channel*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		if (!channel) {
			printf("[ERR] Could not create a local vm-channel\n");
			return 1;
		}

 		static constexpr char vm_magic[16] = "RMV64_II_BEACON";
		auto ch_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, (const uint8_t*)vm_magic, "xxxxxxxxxxxxxxxx");
		if (!ch_offset) {
			printf("[ERR] Could not find the remote vm-channel\n");
			return 1;
		}

		// process vm channel offsets
		if (!rvm64::memory::read_process_memory(proc->handle, ch_offset, (uint8_t*)channel, sizeof(vm_channel))) {
			printf("[ERR] Could not read the remote vm-channel\n");
			return 1;
		}

		// NOTE: populate channel with vm addresses
		auto head_size = sizeof(uint64_t) * 4;
		auto view_size = sizeof(uint64_t) * 3;
		auto ipc_size = sizeof(uint64_t) * 3;

		auto ch_ptr 	= *(uint64_t*)ch_offset + (sizeof(uint64_t) * 2); 					// channel->self (real written VA)
		channel->vmcs 	= *(uint64_t*)ch_offset + (sizeof(uint64_t) * 3);					// channel->vmcs (real written VA)
																							
		auto view_ptr 	= (uint64_t)ch_ptr + head_size;  									// &channel->view
		auto ipc_ptr 	= (uint64_t)ch_ptr + head_size + view_size;  						// &channel->ipc
																							
		channel->view.buffer 		= (uint64_t)view_ptr; 									
		channel->view.size 			= (uint64_t)(view_ptr + sizeof(uint64_t)); 							
		channel->view.write_size 	= (uint64_t)(view_ptr + sizeof(uint64_t) * 2); 						
											 
		channel->ipc.opcode 	= (uint64_t)(ipc_ptr + sizeof(uint64_t));							
		channel->ipc.signal 	= (uint64_t)(ipc_ptr + sizeof(uint64_t) * 2);						
																			
		channel->ready = (uint64_t)ch_ptr + head_size + view_size + ipc_size; 					
		channel->error = (uint64_t)ch_ptr + head_size + view_size + ipc_size + sizeof(uint64_t) 

		if (!superv::patch::install_entry_hook(proc, channel)) {
			printf("[ERR] Could not install entrypoint hook in the vm\n");
			return 1;
		}
		if (!superv::patch::install_decoder_hook(proc, channel)) {
			printf("[ERR] Could not install decoder hook in the vm\n");
			return 1;
		}

		// NOTE: writing to the channel will trigger the vm to start
		if (!superv::loader::write_elf_file(proc->handle, channel, elf_name)) {
			printf("[ERR] Could not load the elf to the vm channel\n");
			return 1;
		}

		printf("vm should be starting now..\n");
		// superv::start(vmcs);
		
		return 0;
	}
}

void print_usage() {
	printf("usage: superv --process <vm> --elf <riscv_elf>\n");
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
