#ifndef VMENTRY_HPP
#define VMENTRY_HPP
#include <errhandlingapi.h>
#include <setjmp.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmipc.hpp"

#include "vmcode.hpp"
#include "vmelf.hpp"
#include "vmveh.hpp"

namespace rvm64::entry {
	_vmcall void vm_init() {
		veh_handle = AddVectoredExceptionHandler(1, vm_exception_handler);
																	
		vmcs->self = (uint64_t)vmcs;
		vmcs->proc.buffer = (uint64_t)VirtualAlloc(nullptr, PROCESS_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!vmcs->proc.buffer) {
			CSR_SET_TRAP(vmcs->hdw->pc, GetLastError(), 0, 0, 1);
			return;
		}

		vmcs->proc.size   			= PROCESS_BUFFER_SIZE;
		vmcs->proc.write_size 		= (uint64_t)0;
		vmcs->proc.ready 			= (uint64_t)0;

		vmcs->size_ptr 		= (uint64_t)&vmcs->proc.size;
		vmcs->write_size_ptr 	= (uint64_t)&vmcs->proc.write_size;
		vmcs->ready_ptr 		= (uint64_t)&vmcs->proc.ready;

		vmcs->magic1 = VM_MAGIC1;
		vmcs->magic2 = VM_MAGIC2;

		vmcs->hdw = (hardware*)VirtualAlloc(nullptr, sizeof(hardware), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!vmcs->hdw) {
			CSR_SET_TRAP(0, out_of_memory, 0, 0, 1);
		}

		vmcs->hdw->vregs[sp] = (uintptr_t)(vmcs->hdw->vstack + VSTACK_MAX_CAPACITY);
		if (vmcs->cache) {
			rvm64::memory::cache_data(vmcs->proc.buffer, vmcs->proc.write_size);
		}
	}

	_vmcall void vm_exit() {
		RemoveVectoredExceptionHandler(veh_handle);
		veh_handle = 0;

		if (vmcs->proc.buffer) {
			VirtualFree((LPVOID)vmcs->proc.buffer, 0, MEM_RELEASE);
			vmcs->proc.buffer = 0;
		}
		if (vmcs->hdw) {
			VirtualFree(vmcs->hdw, 0, MEM_RELEASE);
			vmcs->hdw = 0;
		}

		vmcs->proc.size   			= 0;
		vmcs->proc.write_size 		= (uint64_t)0;
		vmcs->proc.ready 			= (uint64_t)0;

		vmcs->size_ptr 		= (uint64_t)0;
		vmcs->write_size_ptr 	= (uint64_t)0;
		vmcs->ready_ptr 		= (uint64_t)0;

		vmcs->magic1 = 0;
		vmcs->magic2 = 0;
	}

	_vmcall void vm_entry() {
		volatile void *_pad0 = 0;
		if (setjmp(vmcs->hdw->trap_handler)) {}

		while (true) {
			int32_t opcode = *(int32_t*)vmcs->hdw->pc;

			if (opcode == RV64_RET) {
				if (!PROCESS_MEMORY_IN_BOUNDS(vmcs->hdw->vregs[regenum::ra])) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}
			rvm64::decoder::vm_decode(opcode); 
			vmcs->hdw->pc += 4;
		}
	}
};
#endif // VMENTRY_HPP
