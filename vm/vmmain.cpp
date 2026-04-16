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

	do {
		VmInit (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize); // TODO: Remove context from init. They need to be separate so that SaveRegCtx can happen independently.

		if (!Vmcs->Context->HostContext) {
			SaveHostRegCtx (Vmcs->Context->HostContext);
		}

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
	LoadHostRegCtx (Vmcs->Context->HostContext);
	VmRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);

	return Vmcs->Csr.Cause;
}
