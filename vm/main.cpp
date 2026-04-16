#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"


VM_CALL VOID VmEntry () {
	volatile LPVOID Pad0 = 0;

	if (setjmp (Vmcs->Context->TrapHandle)) { } // NOTE: RETURN FROM INTERUPT
	while (true) {
		INT32 Opcode = *(INT32*) Vmcs->Hdw->Pc;

		if (Opcode == RV64_RET) {
			if (! PROCESS_MEMORY_IN_BOUNDS(Vmcs->Hdw->Regs [RA])) {
				CSR_SET_TRAP(nullptr, EnvExit, 0, 0, 1);
			}
		}

		VmDecode (Opcode); 
		Vmcs->Hdw->Pc += 4;
	}
}

NATIVE_CALL INT32 VmMain (
		_In_ const UINT64 Magic1, 
		_In_ const UINT64 Magic2) 
{
	SaveHostContext ();

	MemoryInit 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // NOTE: init memory/modules.
	LoadImage 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // NOTE: load risc-v image.

	Vmcs->Magic1 = Magic1;
	Vmcs->Magic2 = Magic2;

	PatchAndSetEntry (); 									// NOTE: patch plt -> entrypoint

	if (setjmp (Vmcs->ExitHandler)) {
		goto defer;	
	}

defer:
	MemoryFree ();
	RestoreHostContext ();

	return Vmcs->Csr->Cause;
}

int main () {
	VMCS instance = { };
	Vmcs = &instance;

	// TODO: incoming packets/supervisor will assign random magics
    return VmMain (MAGIC_1, MAGIC_2);
}

