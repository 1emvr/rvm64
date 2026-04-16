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

	VM_CALL VOID MemoryInit () {
		Vmcs->Context->VehHandle = AddVectoredExceptionHandler (1, ExceptionHandler);
																	
		Vmcs->Self 			= (UINT64) Vmcs;
		vmcs->Proc.Memory 	= (UINT64) VirtualAlloc(nullptr, DEFAULT_PROC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!Vmcs->Proc.Memory) {
			CSR_SET_TRAP(Vmcs->Gpr->Pc, GetLastError (), 0, 0, 1);
			return;
		}

		Vmcs->Proc.MemorySize   = DEFAULT_PROC_SIZE;
		Vmcs->Proc.Ready 		= (UINT64)0;

		Vmcs->Context = (VM_CONTEXT*) VirtualAlloc (nullptr, sizeof (VM_CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!Vmcs->Context) {
			CSR_SET_TRAP(0, OutOfMemory, 0, 0, 1);
		}

		Vmcs->Hdw.Regs [SP] = (UINT_PTR)(Vmcs->Hdw->Stack + sizeof (Vmcs->Hdw.Stack));
	}

	VM_CALL void VmMemoryFree() {
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

		vmcs->proc.size   		= 0;
		vmcs->proc.write_size 	= (UINT64)0;
		vmcs->proc.ready 		= (UINT64)0;

		vmcs->size_ptr 			= (UINT64)0;
		vmcs->write_size_ptr 	= (UINT64)0;
		vmcs->ready_ptr 		= (UINT64)0;

		vmcs->magic1 = 0;
		vmcs->magic2 = 0;
	}

	VM_CALL void VmEntry() {
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
#endif // VMENTRY_HPP
