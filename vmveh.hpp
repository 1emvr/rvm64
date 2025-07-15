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

	// TODO: test this. fatal exceptions don't seem to return correctly.
	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		restore_host_context();
		winctx->Rip = vmcs->exit_handler.rip;
		winctx->Rsp = vmcs->exit_handler.rsp;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (winctx->ContextFlags & CONTEXT_CONTROL) {
		winctx->EFlags &= ~0x100;
	}
	switch (vmcs->csr.m_cause) {
		case environment_branch: {
			winctx->Rip = vmcs->trap_handler.rip;
			winctx->Rsp = vmcs->trap_handler.rsp;
			break;
		}
		case environment_call_native: {
			rvm64::rvni::vm_native_call();
			vmcs->halt = 0;
			break;
		}
		default:
			// panic
			break;
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
