#ifndef VMVEH_H
#define VMVEH_H
#include <setjmp.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

#include "rvni.hpp"

LONG CALLBACK InteruptHandler (PEXCEPTION_POINTERS ExceptionInfo) {
	DWORD Code 		= ExceptionInfo->ExceptionRecord->ExceptionCode;
	CONTEXT *WinCtx = ExceptionInfo->ContextRecord;

	Vmcs->Csr.Cause 	= Code;
	Vmcs->Csr.Epc 		= WinCtx->Rip;

	if (Code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	if (Vmcs->Halt || Code != RVM_TRAP_EXCEPTION) {
		longjmp (Vmcs->ExitHandler, true);
	}

	switch (Vmcs->Csr.Cause) {
		case ENV_EXIT: 		longjmp (Vmcs->ExitHandler, true);
		case ENV_BRANCH: 	longjmp (Vmcs->TrapHandler, true);
		case ENV_EXECUTE:
		{
			VOID (WINAPI *Memory) (VOID) = (VOID (WINAPI*) (VOID)) Vmcs->Gpr->Pc;
			Memory ();
			break;
		}
		case ENV_NATIVE: 
		{
			NativeCall ();
			break;
		}
		default: 
			break;
	}

	RegRead (UINT_PTR, Vmcs->Gpr.Pc, Regenum::Ra); 
	longjmp (Vmcs->TrapHandler, true); 
}
#endif //VMVEH_H
