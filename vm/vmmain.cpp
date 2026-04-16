#include <windows.h>
#include "vmmain.hpp"


// TODO: StackSpoof, CreateThread, and interact where it lives.

NATIVE_CALL VOID VmMain () {
	if (setjmp (Vmcs->Context->Interrupt)) { } 
	do{
		if (Vmcs->Proc.Memory) {
			MemoryRelease (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize);
		}

		MemoryInit (&Vmcs->Proc.Memory, &Vmcs->Proc.MemorySize); 
		while (Vmcs->Context.Halt) { 
			Sleep (10); 
		}

		LoadImage 		(Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 
		PatchAndExecute (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); 		

		if (setjmp (Vmcs->Context->Shutdown)) { 
			return;	
		}
	} while (true);
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

	LoadRegisters (&Vmcs->Context->HostContext);
	ContextRelease (&Vmcs->Context);
}
