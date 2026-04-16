#include <windows.h>
#include "vmmain.hpp"


// TODO: StackSpoof, CreateThread, and interact where it lives.

NATIVE_CALL VOID rvm64_main () {
	if (setjmp (vmcs->context->shutdown)) { 
		return;	
	}

	while (;;) {
		// NOTE: in the context of sleepobf do we really want to continue looping forever? prob not...
		// would probably crash or never sleep
		//
		// NOTE: how do we process multiple programs? do we need to?
		run_packets ();		
	}
}


NATIVE_CALL VOID proc_main () {
}


NATIVE_CALL VOID rvm64_start (
		_In_ const UINT64 magic1,
		_In_ const UINT64 magic2) 
{
	VMCS instance = { };
	vmcs = &instance;

	rvm64_init (&vmcs->ctx); // NOTE: create global context for all vms.
	rvm64_save_reg (&vmcs->ctx->host_ctx);

	rvm64_main ();

	rvm64_load_reg (&vmcs->ctx->host_ctx);
	rvm64_release (&vmcs->ctx); // NOTE: release context.
}
