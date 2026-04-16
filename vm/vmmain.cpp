#include <windows.h>
#include "vmmain.hpp"


NATIVE_CALL INT32 VmMain (
		_In_ const UINT64 Magic1, 
		_In_ const UINT64 Magic2) 
{
	VMCS Instance = { };
	Vmcs = &Instance;

	Vmcs->Magic1 = Magic1;
	Vmcs->Magic2 = Magic2;

	SaveHostRegCtx ();
	do {
		VmInit (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize); 
		Vmcs->Context->Ready = 1;

		while (Vmcs->Context.Halt) { // machine halts until supervisor triggers.
			Sleep (10);
		}

		LoadImage (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 
		PatchAndExecute (Vmcs->Proc.Memory); 		

		VmRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
		if (setjmp (Vmcs->Context->ExitHandler)) {
			goto defer;	
		}
	} while (true);

defer:
	VmFree ();
	LoadHostRegCtx ();

	return Vmcs->Csr.Cause;
}
