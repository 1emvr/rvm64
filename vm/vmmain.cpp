#include <windows.h>
#include "vmmain.hpp"


#define MAX_VM_THREADS 5
struct PACKET_SEG { 
	UINT_PTR 	image_offset [MAX_VM_THREADS]; 
	UINT_PTR 	param_offset [MAX_VM_THREADS];
	SIZE_T 		count; 
};


NATIVE_CALL BOOL is_elf (_In_ UINT_PTR base) {
	return base [EI_MAG0] == ELFMAG0 && base [EI_MAG1] == ELFMAG1 && 
			base [EI_MAG2] == ELFMAG2 && base [EI_MAG3] == ELFMAG3;
}


NATIVE_CALL BOOL process_packets ( 
// Process our packed ELF files and their params for thread creation. 
// PLT_GOT will be dynamically resolved / addresses relocated in the arena. 
		_Inout_ 	UINT_PTR* 		data,
		_Inout_ 	UINT_PTR* 		data_size,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT_PTR image_base = *data;
	UINT_PTR total = 0;
	
	UINT_PTR n_threads = image_base [0]; // number of files prepended to the start of the packet (n_threads), (param/data)...
	image_base += sizeof (UINT_PTR); 

	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	for (int i = 0; i < n_threads; i++) { 
		UINT_PTR param_size = image_base [0];
		{
			if (param_size != 0) {						
				new_vms->param_offset [i] = image_base; // param_offset points to the header of the param first -> (param size), (*param data)
			}

			total 		+= sizeof (UINT_PTR) + param_size;
			image_base 	+= sizeof (UINT_PTR) + param_size;

			new_vms->image_offset [i] = image_base;

			if (total > *data_size) {	
				arena_realloc (data, data_size, *(data_size) + DEFAULT_ARENA_SIZE);
				image_base = *data + total;
			}
		}
		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;
		SIZE_T prg_size  = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);	
		{
			for (int i = 0; i < ehdr->e_phnum; i++) {
				ELF64_PHDR *phdr 	= (ELF64_PHDR*) (image_base + ehdr->e_phoff + (i * ehdr->e_phentsize));
				UINT_PTR sg_end 	= phdr->p_offset + phdr->p_filesz;

				if (sg_end > prg_size) {
					prg_size = sg_end;
				}
			}

			total 		+= prg_size; 
			image_base 	+= prg_size;

			if (total > *data_size) {	// since programs can expand in memory we need to check to make sure we have enough.
				arena_realloc (data, data_size, *(data_size) + DEFAULT_ARENA_SIZE);
				image_base = *data + total;
			}
		}

		new_vms->count += 1;
	}
	return true;
}


NATIVE_CALL VOID rvm64_main (
		_In_ const UINT_PTR* data, 	// data points to a pre-made arena
		_In_ const UINT_PTR* data_size) 
{
	HANDLE threads [MAX_VM_THREADS] = { };		// might change it to 5 max threads idk
	PACKET_SEG new_vms = { };

	process_packets (&data, &new_vms); // track params, elf data and offsets 
	if (new_vms.count == 0) {
		return;
	}

	for (UINT8 i = 0; i < new_vms.count; i++) {
		UINT_PTR image = data + new_vms.image_offset [i];
		UINT_PTR params = data + new_vms.params_offset [i];

		threads [i] = CreateThread (nullptr, 0, vm_thread (data, image), params, 0, nullptr);
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
