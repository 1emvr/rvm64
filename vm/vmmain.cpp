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
		_Inout_ 	UINT_PTR* 		data_sz,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT_PTR image_base = *data;
	UINT_PTR n_threads 	= image_base [0]; 

	UINT_PTR remaining 	= *data_sz;
	UINT_PTR offset 	= 0;

	offset 		+= sizeof (UINT_PTR);
	image_base 	+= offset; 
	remaining 	-= offset; 

	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	while (n_threads != 0) { 
		UINT_PTR param_sz = image_base [0]; // packed data is [param (size/data), elf (data)], ... 

		if (param_sz != 0) {						
			new_vms->param_offset [i] = offset; 
		}

		offset 		+= sizeof (UINT_PTR) + param_sz;
		image_base 	+= offset;
		remaining 	-= offset;

		new_vms->image_offset [i] = offset; 

		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;
		UINT_PTR img_sz = ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize);	

		for (int i = 0; i < ehdr->e_phnum; i++) { 
			ELF64_PHDR *phdr = (ELF64_PHDR*) (image_base + ehdr->e_phoff + (i * ehdr->e_phentsize));

			if (phdr->p_type != PT_LOAD) {
				continue;
			}

			UINT_PTR img_end = phdr->v_addr + phdr->p_memsz;

			if (img_end > img_sz) { // if img_end > img_size it means we need to reserve space and move the next elf forward
				img_sz = img_end;

				if (image_base + img_sz > remaining) {
					UINT_PTR expand = DEFAULT_ARENA_SIZE + img_sz; 

					remaining += expand;
					arena_realloc (data, data_sz, *(data_sz) + expand);

					image_base = *data + offset;
				}
				// here we move memory of the next elf forward and reserve memory for this one.
			}
		}

		offset 		+= img_sz;
		image_base 	+= offset;
		remaining 	-= offset;

		if (total > *data_sz) {	
			arena_realloc (data, data_sz, *(data_sz) + DEFAULT_ARENA_SIZE);
			image_base = *data + offset;
		}

		new_vms->count 	+= 1;
		n_threads 		-= 1;
	}
	return true;
}


NATIVE_CALL VOID rvm64_main (
		_In_ const UINT_PTR* data, 	// data points to a pre-made arena
		_In_ const UINT_PTR* data_sz) 
{
	HANDLE threads [MAX_VM_THREADS] = { };		
	PACKET_SEG new_vms = { };

	if (!process_packets (data, data_sz, &new_vms)) { // track param_base / elf data offsets 
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
		_In_ const UINT_PTR* data_sz) // should rvm64_start handle the arena, or leave it to another module?
{
	VMCS instance = { };
	vmcs = &instance; // a global vmcs instance to track everything (?)

	rvm64_init (&vmcs->ctx); 
	rvm64_save_reg (&vmcs->ctx->host_ctx);

	rvm64_main (data, data_sz); // TODO: arena_allocate () 

	rvm64_load_reg (&vmcs->ctx->host_ctx);
	rvm64_release (&vmcs->ctx); // release context
}
