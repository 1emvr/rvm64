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

	ContextInit (&Vmcs->Context);
	SaveHostRegCtx (Vmcs->Context->HostContext);

	do {
		MemoryInit (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize); 
		Vmcs->Context->Ready = 1;

		while (Vmcs->Context.Halt) { // machine halts until supervisor triggers.
			Sleep (10);
		}

		LoadImage (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 
		PatchAndExecute (Vmcs->Proc.Memory); 		

		MemoryRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
		if (setjmp (Vmcs->Context->Shutdown)) { 
			goto defer;	
		}
	} while (true);

defer:
	LoadHostRegCtx (Vmcs->Context->HostContext);

	MemoryRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
	ContextRelease (&Vmcs->Context);

	return Vmcs->Csr.Cause;
}
