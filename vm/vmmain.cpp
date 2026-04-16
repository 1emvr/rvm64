#include <windows.h>
#include "vmmain.hpp"


struct PACKET_SEG { 
	UINT_PTR 	files	[8]; 
	UINT_PTR 	params 	[8];
	SIZE_T 		count; 
};


NATIVE_CALL BOOL is_elf (_In_ const UINT_PTR base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL VOID process_packets ( // process ELF params and headers
		_In_ const UINT_PTR 	data,
		_In_ const PACKET_SEG* 	new_vms,
		_In_ const SIZE_T 		arena_size) 
{
	UINT_PTR 	image_base = data;
	SIZE_T 		total_size = 0;

	for (UINT8 i = 0; i < 8; i++) {
		// PARAM_MAGIC, 
		// PARAM_SIZE, 
		// PARAM_DATA -> ELF
		if (is_param (image_base)) {
			SIZE_T param_size = *(SIZE_T*)image_base + 2; // ... or whatever

			new_vms->params [i] = image_base;
			image_base += param_size + PARAM_HEADER_SIZE;
		}
		if (!is_elf (image_base)) {
			return;
		}

		UINT8 elf_class = image_base [EI_CLASS];

		if (elf_class == ELFCLASS64) {
			ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;
			// if we want to do bounds checking on the arena for these programs we'll need to pass the arena size.
			// this way we could also reallocate quickly if we need to.
		}
	}
}


NATIVE_CALL VOID rvm64_main (
		_In_ const UINT_PTR data,
		_In_ const SIZE_T	size) 
{
	HANDLE threads [8] = { };			
	PACKET_SEG new_vms = { };

	process_packets (data, &new_vms); // track params (magic, params size, param data)-> nt_head + file size
									
	if (new_vms.count == 0) {
		return;
	}

	for (UINT8 i = 0; i < new_vms.count; i++) {
		threads [i] = CreateThread (
				nullptr, 0, 
				vm_thread (data, new_vms.files [i]), 
				new_vms.params [i], 
				0, nullptr);
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
