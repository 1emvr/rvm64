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


NATIVE_CALL VOID thread_main () {
	return;
}


NATIVE_CALL BOOL process_packets ( 
// Process our packed ELF files and their param_base for thread creation. 
// PLT_GOT will be dynamically resolved / addresses relocated in the arena. 
		_Inout_ 	UINT_PTR* 		data,
		_Inout_ 	UINT_PTR* 		data_size,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT_PTR image_base = *data;
	
	UINT_PTR n_threads = image_base [0]; // number of files prepended to the start of the packet (n_threads), (param/data)...
	UINT_PTR total = sizeof (UINT_PTR);

	image_base += total; 

	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	for (int i = 0; i < n_threads; i++) { 
		UINT_PTR param_size = image_base [0]; // packed data is [param (size/data), elf (data)], ... 
		{
			if (param_size != 0) {						
				new_vms->param_offset [i] = image_base - *data; // param_offset points to the header of the param-> (param size), (param data)
			}

			total 		+= sizeof (UINT_PTR) + param_size;
			image_base 	+= sizeof (UINT_PTR) + param_size;

			new_vms->image_offset [i] = image_base - *data; 
			// honest to god we don't really need to consider if a parameter is beyond the arena unless it's a malformed packet, and then we have larger problems...
			// we should be more worried about expanding the ELF data, and that's when I would perform bounds checking.
		}

		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;
		SIZE_T img_size  = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);	
		{
			for (int i = 0; i < ehdr->e_phnum; i++) {
				ELF64_PHDR *phdr 	= (ELF64_PHDR*) (image_base + ehdr->e_phoff + (i * ehdr->e_phentsize));
				UINT_PTR sg_end 	= phdr->v_addr + phdr->p_memsz;

				if (phdr->p_type != PT_LOAD) {
					continue;
				}
				if (sg_end > img_size) {
					img_size = sg_end;
				}
			}
		}

		total 		+= img_size; 
		image_base 	+= img_size;

		if (total > *data_size) {	// since programs can expand in memory we need to check to make sure we have enough.
			arena_realloc (data, data_size, *(data_size) + DEFAULT_ARENA_SIZE);
			image_base = *data + total;
		}
		new_vms->count += 1;
	}
	return true;
}


NATIVE_CALL VOID rvm64_main (
		_In_ const UINT_PTR* data, 	// data points to a pre-made arena
		_In_ const UINT_PTR* data_size) 
{
	HANDLE threads [MAX_VM_THREADS] = { };		
	PACKET_SEG new_vms = { };

	if (!process_packets (data, data_size, &new_vms)) { // track param_base / elf data offsets 
		goto defer;
	}
	if (new_vms.count == 0) {
		return;
	}

	for (int i = 0; i < new_vms.count; i++) {
		UINT_PTR image_base = *data + new_vms.image_offset [i];
		UINT_PTR param_base = *data + new_vms.param_offset [i];

		if (param_base [0] == 0) {
			param_base = nullptr;
		}

		threads [i] = CreateThread (nullptr, 0, vm_thread (image_base), param_base, 0, nullptr); // TODO: redesign vmcs to handle multiple threads
	}

	WaitForMultipleObjects (new_vms.count, &threads, true, 5000);
	// post_thread_response () ??
	//
defer:
	// arena_release () ??
}


NATIVE_CALL VOID rvm64_start (
		_In_ const UINT_PTR* data,
		_In_ const UINT_PTR* data_size) // should rvm64_start handle the arena, or leave it to another module?
{
	VMCS instance = { };
	vmcs = &instance; // a global vmcs instance to track everything (?)

	rvm64_init (&vmcs->ctx); 
	rvm64_save_reg (&vmcs->ctx->host_ctx);

	rvm64_main (data, data_size); // TODO: arena_allocate () 

	rvm64_load_reg (&vmcs->ctx->host_ctx);
	rvm64_release (&vmcs->ctx); // release context
}
