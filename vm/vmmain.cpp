#include <windows.h>
#include "vmmain.hpp"


NATIVE_CALL VOID VmMain () {
	if (setjmp (Vmcs->Context->Interrupt)) { 
		Sleep (10);
	}
	do {
		MemoryInit (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize); 
		Vmcs->Context->Ready = 1;

		while (Vmcs->Context.Halt) { // machine halts until supervisor triggers.
			Sleep (10);
		}

		LoadImage (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 
		PatchAndExecute (Vmcs->Proc.Memory); 		

		if (setjmp (Vmcs->Context->Shutdown)) { 
			goto defer;	
		}

		MemoryRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
	} while (true);

defer:
	MemoryRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
	LoadRegisters (&Vmcs->Context->HostContext);
}


NATIVE_CALL VOID VmStart (
		_In_ const UINT64 Magic1,
		_In_ const UINT64 Magic2) 
{
	VMCS Instance = { };
	Vmcs = &Instance;

	Vmcs->Magic1 = Magic1;
	Vmcs->Magic2 = Magic2;

	ContextInit (&Vmcs->Context);
	SaveRegisters (&Vmcs->Context->HostContext);

	VmMain ();
	ContextRelease (&Vmcs->Context);
}
