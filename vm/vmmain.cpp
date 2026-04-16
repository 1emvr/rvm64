#include <windows.h>
#include "vmmain.hpp"
#include "vmcommon.hpp"


VM_CALL VOID SetCsrTrap (
		_In_ const INT Epc, 
		_In_ const INT Cause, 
		_In_ const INT Stat, 
		_In_ const INT Tval, 
		_In_ const INT Halt) 
{
    Vmcs->Csr->Epc 		= (UINT_PTR)Epc;			
    Vmcs->Csr->Cause 	= Cause;                 	
    Vmcs->Csr->Status 	= Stat;                 	
    Vmcs->Csr->Tval 	= Tval;                    
    Vmcs->Context->Halt = Halt;                    

    RaiseException (RVM_TRAP_EXCEPTION, 0, 0, nullptr); 	
}


VM_CALL VOID VmExecute () {
	if (setjmp (Vmcs->Context->TrapHandler)) { } 

	while (Vmcs->Context.Halt) {
		Sleep (10);
	}
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

	PatchImage (); // patch plt/entrypoint
	VmExecute ();

	if (setjmp (Vmcs->Context->ExitHandler)) {
		goto defer;	
	}

defer:
	MemoryFree ();
	RestoreHostContext ();

	return Vmcs->Csr.Cause;
}
