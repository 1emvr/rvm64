#ifndef VMVEH_H
#define VMVEH_H
#include <setjmp.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

#include "rvni.hpp"
#define LONGJMP(addr, b) longjmp(addr, b); VM_UNREACHABLE()

LONG CALLBACK vm_exception_handler(PEXCEPTION_POINTERS exception_info) {
	CONTEXT *winctx = exception_info->ContextRecord;
	DWORD code = exception_info->ExceptionRecord->ExceptionCode;

	if (code == STATUS_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	vmcs->hdw->csr.m_cause = code;
	vmcs->hdw->csr.m_epc = winctx->Rip;

	winctx->EFlags &= ~0x100;  // Clear TF before returning

	if (vmcs->halt || code != RVM_TRAP_EXCEPTION) {
		LONGJMP(vmcs->hdw->exit_handler, true);
	}
	switch (vmcs->hdw->csr.m_cause) {
		case environment_exit: 		LONGJMP(vmcs->hdw->exit_handler, true);
		case environment_branch: 	__debugbreak(); LONGJMP(vmcs->hdw->trap_handler, true);
		case environment_execute:
		{
			void (__stdcall *memory)() = (void(__stdcall*)())vmcs->hdw->pc;
			memory();
			break;
		}
		case environment_call_native: 
		{
			__debugbreak(); rvm64::rvni::vm_native_call();
			break;
		}
		default: break;
	}

	reg_read(uintptr_t, vmcs->hdw->pc, regenum::ra); 
	LONGJMP(vmcs->hdw->trap_handler, true); 
}
#endif //VMVEH_H
