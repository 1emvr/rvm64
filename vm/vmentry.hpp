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

		Vmcs->Context->VehHandle = AddVectoredExceptionHandler (1, ExceptionHandler);
		Vmcs->Hdw.Regs [SP] = (UINT_PTR)(Vmcs->Hdw->Stack + sizeof (Vmcs->Hdw.Stack));
	}

	VM_CALL VOID MemoryFree () {
		RemoveVectoredExceptionHandler (Vmcs->Context->VehHandle);
		Vmcs->Context->VehHandle = 0;

		if (Vmcs->Proc.Memory) {
			VirtualFree ((LPVOID)Vmcs->Proc.Memory, 0, MEM_RELEASE);
			Vmcs->Proc.Memory = 0;
		}

		vmcs->Proc.MemorySize   = 0;
		vmcs->Proc.Ready 		= 0;

		Vmcs->Magic1 = 0;
		Vmcs->Magic2 = 0;
	}

	VM_CALL VOID VmEntry () {
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
