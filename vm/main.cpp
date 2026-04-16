#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"

#include "vmentry.hpp"

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

