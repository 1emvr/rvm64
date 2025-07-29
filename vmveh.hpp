#ifndef VMVEH_H
#define VMVEH_H
#include <setjmp.h>

#include "vmmain.hpp"
#include "vmmem.hpp"
#include "rvni.hpp"


#define LONGJMP(addr, b) longjmp(addr, b); __builtin_unreachable()

LONG CALLBACK vm_exception_handler(PEXCEPTION_POINTERS exception_info) {
	CONTEXT *winctx = exception_info->ContextRecord;
	DWORD code = exception_info->ExceptionRecord->ExceptionCode;

	if (code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CSR_GET(exception_info);
	winctx->EFlags &= ~0x100;  // Clear TF before returning
							   
	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		LONGJMP(vmcs->exit_handler, true);
	}
							   //
	switch (vmcs->csr.m_cause) {
		case environment_exit: 		LONGJMP(vmcs->exit_handler, true);
		case environment_branch: 	LONGJMP(vmcs->trap_handler, true);
		case environment_execute:   
		{
			__debugbreak();
			void (__stdcall *memory)() = (void(__stdcall*)())vmcs->pc;
			memory();
			vmcs->pc = vmcs->vregs[ra];
			break;
		}
		case environment_call_native: 
		{
			__debugbreak();
			rvm64::rvni::vm_native_call();
			vmcs->pc = vmcs->vregs[ra];
			break;
		}
		default: 
		{
			__debugbreak();
			break;
		}
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
