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
	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		winctx->Rip = vmcs->host_context.rip;
		winctx->Rsp = vmcs->host_context.rsp;
		winctx->Rbp = vmcs->host_context.rbp;
		winctx->Rbx = vmcs->host_context.rbx;
		winctx->R12 = vmcs->host_context.r12;
		winctx->R13 = vmcs->host_context.r13;
		winctx->R14 = vmcs->host_context.r14;
		winctx->R15 = vmcs->host_context.r15;

		winctx->EFlags = (DWORD)vmcs->host_context.rflags;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (winctx->ContextFlags & CONTEXT_CONTROL) {
		winctx->EFlags &= ~0x100; // remove trap flag
	}
	if (vmcs->csr.m_cause == environment_call_native) {
		rvm64::rvni::vm_native_call();
		vmcs->halt = 0;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
