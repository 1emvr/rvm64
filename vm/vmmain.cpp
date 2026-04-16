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
	{
		SaveHostContext ();
		VmInit (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // init memory/modules.
														   
		Vmcs->Context->Ready = 1;
		while (Vmcs->Context.Halt) {
			Sleep (10);
		}
	}

	LoadImage (Vmcs->Proc.Memory, Vmcs->Proc.MemorySize); // load risc-v image written by the supervisor.
	PatchAndExecute (); 		

	if (setjmp (Vmcs->Context->ExitHandler)) {
		goto defer;	
	}

defer:
	VmFree ();
	RestoreHostContext ();

	return Vmcs->Csr.Cause;
}
