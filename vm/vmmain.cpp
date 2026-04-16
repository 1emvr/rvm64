#include <windows.h>
#include "vmmain.hpp"


struct PACKET_SEG { 
	UINT_PTR 	images	[8]; 
	UINT_PTR 	params 	[8];
	SIZE_T 		count; 
};


NATIVE_CALL BOOL is_elf (_In_ UINT_PTR base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL BOOL process_packets ( // process ELF params and headers
		_Inout_ 	UINT_PTR* 		data,
		_Inout_ 	SIZE_T* 		data_size,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT_PTR image_base = *data;
	SIZE_T total_size = 0;

	for (int i = 0; i < 8; i++) {
		// PARAM_MAGIC, 
		// PARAM_SIZE, 
		// PARAM_DATA -> ELF
		if (is_param (image_base) && remaining >= PARAM_HEADER_SIZE) {
			SIZE_T param_size = *(SIZE_T*)image_base + 2; // ... or however long offset
														  
			param_size += PARAM_HEADER_SIZE;
			total_size += param_size;

			if (total_size > *data_size) { // find a way to make this easy. not too big or too small of a realloc
				arena_realloc (data, data_size, *(data_size) + DEFAULT_PAGE_SIZE);
			}
			new_vms->params [i] = image_base;
			image_base += param_size;
		}

		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		new_vms->images [i] = image_base;
		new_vms->count += 1;

		ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;
		SIZE_T prg_size = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);	

		for (int i = 0; i < ehdr->e_phnum; i++) {
			ELF64_PHDR *phdr = (ELF64_PHDR*)(image + ehdr->e_phoff + (i * ehdr->e_phentsize));
			SIZE_T sg_end = phdr->p_offset + phdr->p_filesz;

			if (sg_end > prg_size) {
				prg_size = sg_end;
			}
		}

		total_size += prg_size;
		if (total_size > data_size) {
			// return false or resize the arena
		}

		image_base += prg_size;
	}
	return true;
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
