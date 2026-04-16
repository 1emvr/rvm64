#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"


VM_CALL VOID VmExecute () {
	volatile LPVOID Pad0 = 0; // Used to align the function ? Added when making the debugger.
	
	if (setjmp (Vmcs->Context->TrapHandler)) { } 

	while (true) {
		INT32 Opcode = *(INT32*) Vmcs->Hdw.Pc;

		if (Opcode == RV64_RET) {
			if (! PROCESS_MEMORY_IN_BOUNDS (Vmcs->Hdw.Regs [RA])) {
				CSR_SET_TRAP (nullptr, EnvExit, 0, 0, 1);
			}
		}

		VmDecode (Opcode); 
		Vmcs->Hdw.Pc += 4;
	}
}

NATIVE_CALL INT32 VmMain (
		_In_ const UINT64 Magic1, 
		_In_ const UINT64 Magic2) 
{
	SaveHostContext ();

	MemoryInit 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // init memory/modules.
	LoadImage 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // load risc-v image.

	Vmcs->Magic1 = Magic1;
	Vmcs->Magic2 = Magic2;

	PatchImportTable (); 									// patch plt/entrypoint
	VmExecute ();

	if (setjmp (Vmcs->Context->ExitHandler)) {
		goto defer;	
	}

defer:
	MemoryFree ();
	RestoreHostContext ();

	return Vmcs->Csr.Cause;
}

int main () {
	VMCS instance = { };
	Vmcs = &instance;

	// TODO: incoming packets/supervisor will assign random magics
    return VmMain (MAGIC_1, MAGIC_2);
}

