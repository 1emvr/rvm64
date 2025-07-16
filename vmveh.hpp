#ifndef VMVEH_H
#define VMVEH_H
#include <setjmp.h>

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
		longjmp(vmcs->exit_handler, true);
		__builtin_unreachable();
	}

	switch (vmcs->csr.m_cause) {
		case environment_branch: {
			longjmp(vmcs->trap_handler, true);
			__builtin_unreachable();
		}
		case environment_call_native: {
			rvm64::rvni::vm_native_call();
			vmcs->halt = 0;
			break;
		}
		default:
			break;
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}
#endif //VMVEH_H
