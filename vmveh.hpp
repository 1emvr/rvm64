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
	switch (vmcs->csr.m_cause) {
		case environment_exit: 		LONGJMP(vmcs->exit_handler, true);
		case environment_branch: 	LONGJMP(vmcs->trap_handler, true);
		case environment_execute:   
		{
			void (__stdcall *memory)() = (void(__stdcall*)())vmcs->pc;
			memory();
			break;
		}
		case environment_call_native: 
		{
			rvm64::rvni::vm_native_call();
			break;
		}
		default: 
		{
			__debugbreak();
			break;
		}
	}

	reg_read(uintptr_t, vmcs->pc, regenum::ra); 
	LONGJMP(vmcs->trap_handler, true); 

	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
