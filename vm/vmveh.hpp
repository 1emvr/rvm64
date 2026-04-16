#ifndef VMVEH_H
#define VMVEH_H
#include <setjmp.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

#include "rvni.hpp"
#define LONGJMP(addr, b) longjmp(addr, b); VM_UNREACHABLE()

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

	switch (Vmcs->Csr.m_cause) {
		case EnvExit: 	longjmp (Vmcs->ExitHandler, true);
		case EnvBranch: longjmp (Vmcs->TrapHandler, true);
		case EnvExecute:
		{
			VOID (WINAPI *Memory) (VOID) = (VOID (WINAPI*) (VOID)) Vmcs->Gpr->Pc;
			Memory();
			break;
		}
		case EnvNative: 
		{
			VmNativeCall ();
			break;
		}
		default: 
			break;
	}

	RegRead (UINT_PTR, Vmcs->Gpr.Pc, Regenum::Ra); 
	longjmp (Vmcs->TrapHandler, true); 
	
	return 0;
}
#endif //VMVEH_H
