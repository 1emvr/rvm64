#include <windows.h>
#include "vmmain.hpp"


NATIVE_CALL VOID vm_thread (_In_ const LPVOID vm, _In_ const LPVOID vm_params) {
	vm_mem_reserve (vm->mem, vm->mem_size);
	vm_mem_release (vm->mem, vm->mem_size);
}


NATIVE_CALL VOID rvm64_main () {
	HANDLE threads [8] = { } 			

	static struct PACKET_SEG { // process packet + populate with related data
		LPVOID files 	[8] = { }; 
		LPVOID params 	[8] = { };
		SIZE_T count 		= 0; 
	} new_vms;

	process_packets (&new_vms); 	// process packets as a flat array using NT_HEADERS (up to 8)
									// track params (magic, params size, param data)-> nt_head + file size
									// reallocate if all programs exceed arena size
	if (new_vms.count == 0) {
		return;
	}

	for (UINT8 i = 0; i < new_vms.count; i++) {
		threads [i] = CreateThread (nullptr, 0, vm_thread (new_vms.files [i]), new_vms.params [i], 0, nullptr);
	}

	WaitForMultipleObjects (new_vms.count, &threads, true, 5000);
}


NATIVE_CALL VOID proc_main () {
}


NATIVE_CALL VOID rvm64_start (_In_ const LPVOID data)
{
	VMCS instance = { };
	vmcs = &instance;

	rvm64_init (&vmcs->ctx); // NOTE: create global context for all vms.
	rvm64_save_reg (&vmcs->ctx->host_ctx);

	rvm64_main (data);

	rvm64_load_reg (&vmcs->ctx->host_ctx);
	rvm64_release (&vmcs->ctx); // NOTE: release context.
}
