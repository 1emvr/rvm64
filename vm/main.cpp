#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"

NATIVE_CALL INT32 VmMain (_In_ const UINT64 magic1, _In_ const UINT64 magic2) {
	SaveHostContext ();

	MemoryInit 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 
	LoadImage 	(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize);
	PatchAndSetEntry ();

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
    return VmMain (VM_MAGIC1, VM_MAGIC2);
}

