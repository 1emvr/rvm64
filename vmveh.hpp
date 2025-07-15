#ifndef VMVEH_H
#define VMVEH_H
#include "vmmain.hpp"
#include "rvni.hpp"


LONG CALLBACK vm_exception_handler(PEXCEPTION_POINTERS exception_info) {
	CONTEXT *winctx = exception_info->ContextRecord;
	DWORD code = exception_info->ExceptionRecord->ExceptionCode;

	if (code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	CSR_GET(exception_info);

	// TODO: test that VEH jumps back to vm_main -> exit on fatal exceptions
	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		winctx->Rip = vmcs->exit_handler.rip;
		winctx->Rsp = vmcs->exit_handler.rsp;
		winctx->ContextFlags |= CONTEXT_CONTROL;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	switch (vmcs->csr.m_cause) {
		case environment_branch: {
			// NOTE: jump back to vm_loop and don't modify vmcs->pc
			//
			winctx->Rip = vmcs->trap_handler.rip;
			winctx->Rsp = vmcs->trap_handler.rsp;
			winctx->ContextFlags |= CONTEXT_CONTROL;

			break;
		}
		case environment_call_native: {
			// NOTE: vm exit to native api
			//
			rvm64::rvni::vm_native_call();
			vmcs->halt = 0;

			break;
		}
		default:
			// panic!! raaaaah!
			break;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
