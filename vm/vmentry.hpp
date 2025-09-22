#ifndef VMENTRY_HPP
#define VMENTRY_HPP
#include <errhandlingapi.h>
#include <setjmp.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

#include "vmcode.hpp"
#include "vmelf.hpp"
#include "vmveh.hpp"

namespace rvm64::entry {
	_vmcall void vm_init() {
		veh_handle = AddVectoredExceptionHandler(1, vm_exception_handler);
		rvm64::memory::memory_init(vmcs->channel.view.write_size); // using the channel->view for process
																	
		rvm64::elf::load_elf_image(vmcs->channel.view.buffer, vmcs->channel.view.write_size);
		rvm64::elf::patch_elf_plt_and_set_entry();

		vmcs->vregs[sp] = (uintptr_t)(vmcs->vstack + VSTACK_MAX_CAPACITY);
		vmcs->cache
			? rvm64::memory::cache_data(vmcs->channel.view.buffer, vmcs->channel.view.write_size)
			: rvm64::memory::destroy_data(vmcs->channel.view.buffer, vmcs->channel.view.write_size);
	}

	_vmcall void vm_exit() {
		RemoveVectoredExceptionHandler(veh_handle);
		rvm64::memory::memory_end();
	}

	_vmcall void vm_entry() {
		printf("[INF] hit vm_entry\n");
		if (setjmp(vmcs->trap_handler)) {}

		while (true) {
			int32_t opcode = *(int32_t*)vmcs->pc;
			printf("next\n");

			if (opcode == RV64_RET) {
				if (!PROCESS_MEMORY_IN_BOUNDS(vmcs->vregs[regenum::ra])) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}
			rvm64::decoder::vm_decode(opcode); // decoder patch here -> hook for every new ins.
			vmcs->pc += 4;
		}
	}
};
#endif // VMENTRY_HPP
