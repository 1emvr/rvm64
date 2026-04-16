#include <windows.h>
#include "vmmain.hpp"


// TODO: StackSpoof, CreateThread, and interact where it lives.

NATIVE_CALL VOID vm_thread (_In_ const PACKET* packet) {
	vm_mem_init ();
}

NATIVE_CALL VOID rvm64_main () {
	HANDLE threads [8] = { } // max of 8 parallel threads
							 
	check_packets ();		
	for (int i = 0; i < packet_num; i++) {
		threads [i] = CreateThread (nullptr, 0, vm_thread (new_vm), &params, 0, nullptr);
	}

	WaitForMultipleObjects (packet_num, &packets, true, 5000);
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
