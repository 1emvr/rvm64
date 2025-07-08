#ifndef VMVEH_H
#define VMVEH_H
#include "vmmain.hpp"
#include "rvni.hpp"

VOID vm_restore_original(CONTEXT *winctx, UINT_PTR exit_handler) {
	winctx->Rip = exit_handler;
	winctx->Rsp = vmcs->host_context.rsp;
	winctx->Rbp = vmcs->host_context.rbp;
	winctx->Rax = vmcs->host_context.rax;
	winctx->Rbx = vmcs->host_context.rbx;
	winctx->Rcx = vmcs->host_context.rcx;
	winctx->Rdx = vmcs->host_context.rdx;
	winctx->R8	= vmcs->host_context.r8;
	winctx->R9	= vmcs->host_context.r9;
	winctx->R10 = vmcs->host_context.r10;
	winctx->R11 = vmcs->host_context.r11;
	winctx->R12 = vmcs->host_context.r12;
	winctx->R13 = vmcs->host_context.r13;
	winctx->R14 = vmcs->host_context.r14;
	winctx->R15 = vmcs->host_context.r15;
	winctx->EFlags = (DWORD) vmcs->host_context.rflags;
}

LONG CALLBACK vm_exception_handler(PEXCEPTION_POINTERS exception_info) {
	CONTEXT *winctx = exception_info->ContextRecord;
	DWORD code = exception_info->ExceptionRecord->ExceptionCode;

	if (code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	CSR_GET(exception_info);

	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		vm_restore_original(winctx, vmcs->exit_handler);
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
