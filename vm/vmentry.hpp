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
																	
		vmcs->hdw = (hardware*)VirtualAlloc(nullptr, sizeof(hardware), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!vmcs->hdw) {
			CSR_SET_TRAP(0, out_of_memory, 0, 0, 1);
		}

		rvm64::elf::load_elf_image(vmcs->proc.buffer, vmcs->proc.write_size);
		rvm64::elf::patch_elf_plt_and_set_entry();

		vmcs->hdw.vregs[sp] = (uintptr_t)(vmcs->hdw.vstack + VSTACK_MAX_CAPACITY);
		if (vmcs->cache) {
			rvm64::memory::cache_data(vmcs->proc.buffer, vmcs->proc.write_size);
		}
	}

	_vmcall void vm_exit() {
		RemoveVectoredExceptionHandler(veh_handle);
	}

	_vmcall void vm_entry() {
		volatile void *_pad0 = 0;
		if (setjmp(vmcs->trap_handler)) {}

		while (true) {
			int32_t opcode = *(int32_t*)vmcs->hdw.pc;

			if (opcode == RV64_RET) {
				if (!PROCESS_MEMORY_IN_BOUNDS(vmcs->hdw.vregs[regenum::ra])) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}
			__debugbreak();
			rvm64::decoder::vm_decode(opcode); 
			vmcs->hdw.pc += 4;
		}
	}
};
#endif // VMENTRY_HPP
