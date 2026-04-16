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
		_Inout_ 	UINT_PTR* 		data,
		_Inout_ 	UINT_PTR* 		data_sz,
		_Out_ 		PACKET_SEG* 	new_vms)
{
	UINT8 *image_base = (UINT8*)*data;

	UINT_PTR n_threads 	= image_base [0]; 
	UINT_PTR remaining 	= *data_sz;
	UINT_PTR offset 	= 0;

	offset 		+= sizeof (UINT_PTR);
	image_base 	+= sizeof (UINT_PTR); 
	remaining 	-= sizeof (UINT_PTR); 

	if (n_threads == 0 || n_threads > MAX_VM_THREADS) {
		return false;
	}

	for (int i = 0; i < n_threads; i++) { 
		UINT_PTR param_sz = image_base [0]; // packed data is [param (size/data), elf (data), (_pt_load_space)], ... 
											//
		if (param_sz != 0) {						
			new_vms->param_offset [i] = offset; 
		}

		offset 		+= sizeof (UINT_PTR) + param_sz;
		image_base 	+= sizeof (UINT_PTR) + param_sz;
		remaining 	-= sizeof (UINT_PTR) + param_sz;

		new_vms->image_offset [i] = offset; 

		if (!is_elf (image_base) || image_base [EI_CLASS] != ELFCLASS64) {
			return false;
		}

		ELF64_EHDR *ehdr = (ELF64_EHDR*)image_base;

		UINT_PTR lo = (UINT_PTR)-1, hi = 0;
		UINT_PTR file_sz = 0;	

		file_sz = max (
				file_sz, 
				(UINT_PTR)ehdr->e_phoff + (UINT_PTR)ehdr->e_phnum * ehdr->e_phentsize); // figure out why there's 3 different ways to determine the file size

		if (ehdr->e_shoff) {
			file_sz = max (
					file_sz, 
					(UINT_PTR)ehdr->e_shoff + (UINT_PTR)ehdr->e_shnum * ehdr->e_shentsize);
		}
		{
			for (int i = 0; i < ehdr->e_phnum; i++) { 
				ELF64_PHDR *phdr = (ELF64_PHDR*) (image_base + ehdr->e_phoff + (i * ehdr->e_phentsize));
				file_sz = max (
						file_sz, 
						(UINT_PTR)phdr [i].p_offset + (UINT_PTR)phdr [i].p_filesz);

				if (phdr->p_type != PT_LOAD) {
					continue;
				}

				UINT_PTR seg_lo = phdr->p_vaddr & ~(phdr->p_align - 1);
				UINT_PTR seg_hi = phdr->p_vaddr + phdr->p_memsz;

				if (seg_lo < lo) { lo = seg_lo; }
				if (seg_hi > hi) { hi = seg_hi; }
			}
		}

		UINT_PTR expanded = hi - lo;
		UINT_PTR delta = expanded - file_sz;

		offset 		+= img_sz;
		image_base 	+= img_sz;
		remaining 	-= img_sz;

		if (total > *data_sz) {	
			arena_realloc (data, data_sz, *(data_sz) + DEFAULT_ARENA_SIZE);
			image_base = *data + offset;
		}

		new_vms->count += 1;
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
