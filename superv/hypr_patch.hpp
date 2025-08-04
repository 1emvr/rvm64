#ifndef HYPRPATCH_HPP
#define HYPRPATCH_HPP
#include <windows.h>

#include "hypr_proc.hpp"
#include "../vmmain.hpp"


namespace superv::patch {
	_data uint8_t entry_sig[] = {
		0x48, 0x89, 0x05, 0x01, 0x3f, 0x01, 0x00, 	// 0x00: mov     cs:vmcs, rax
		0xe8, 0x00, 0x00, 0x00, 0x00,             	// 0x07: call    rvm64::entry::vm_entry(void)
		0x48, 0x8b, 0x05, 0xf5, 0x3e, 0x01, 0x00,  	// 0x0c: mov     rax, cs:vmcs
	};

	_data uint8_t entry_hook[] = {
		0x0f, 0xb6, 0x05, 0x00, 0x00, 0x00, 0x00,   // movzx eax, byte ptr [rip+disp32]
		0x84, 0xc0,                                 // test al, al
		0x75, 0xf5,                                 // jne -0xb
		0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov byte ptr [rip+disp32], 0
		0xe9, 0x00, 0x00, 0x00, 0x00,               // jmp rel32
	};

	bool install_entry_patch(process_t *proc, mapped_view* shbuf) {
		size_t stub_size = sizeof(entry_hook);

		uintptr_t hook_addr = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_addr) {
			return false;
		}

		uintptr_t entry_offset = superv::process::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig, "xxxxxxxx????xxxxxxx");
		if (!entry_offset) {
			return false;
		}

		uintptr_t entry_call = entry_offset + 7;
		int32_t original_rel = 0;

		if (!superv::process::memory::read_proc_memory(proc->handle, entry_call + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			return false;
		}

		uintptr_t original_entry = entry_call + 5 + original_rel;
		uintptr_t signal = &shbuf->ipc.signal;
		{
			// modifying the stub: getting RIP-displaced addresss to shmem->signal + vm_entry and 
			int32_t rel1 = (int32_t)(signal - (hook_addr + 0x07));
			memcpy(&entry_hook[0x03], &rel1, sizeof(rel1));

			int32_t rel2 = (int32_t)(signal - (hook_addr + 0x12));
			memcpy(&entry_hook[0x0D], &rel2, sizeof(rel2));

			int32_t entry_rel = (int32_t)(original_entry - (hook_addr + 0x17));
			memcpy(&entry_hook[0x13], &entry_rel, sizeof(entry_rel));
		}

		if (!superv::process::memory::write_proc_memory(proc->handle, hook_addr, entry_hook, sizeof(entry_hook))) {
			return false;
		}

		int32_t hook_offset = (int32_t)(hook_addr - (entry_call + 5));
		if (!superv::process::memory::write_proc_memory(proc->handle, entry_call + 1, (uint8_t*)&hook_offset, sizeof(hook_offset))) {
			return false;
		}

		return true;
	}

	_data uint8_t decoder_sig[] = { 
		0x8B, 0x45, 0xFC,							// 0x00: mov     eax, [rbp+opcode]
		0x89, 0xC1,                                 // 0x03: mov     ecx, eax        ; opcode
		0xE8, 0x00, 0x00, 0x00, 0x00,               // 0x05: call    rvm64::decoder::vm_decode(uint)
		0x48, 0x8B, 0x05, 0x75, 0x3F, 0x01, 0x00,   // 0x0a: mov     rax, cs:vmcs
	};

	uint8_t decoder_hook[] = {
		0x41, 0x53,                               	// push r11
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,    	// lea  r11, [rip+disp32]   ; -> &mapped_view->ipc.opcode
		0x41, 0x89, 0x03,                         	// mov  dword ptr [r11], eax
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,    	// lea  r11, [rip+disp32]   ; -> &mapped_view->ipc.vmcs
		0x49, 0x89, 0x0B,                         	// mov  qword ptr [r11], rcx
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,    	// lea  r11, [rip+disp32]   ; -> &mapped_view->ipc.signal
		0x41, 0x80, 0x3B, 0x00,                   	// cmp  byte ptr [r11], 0
		0x75, 0xFA,                               	// jne  -6                  ; spin while signal != 0
		0x48, 0x83, 0xEC, 0x28,                   	// sub  rsp, 0x28           ; Win64 shadow + align
		0xE8, 0x00,0x00,0x00,0x00,                	// call rel32               ; -> vm_decode
		0x48, 0x83, 0xC4, 0x28,                   	// add  rsp, 0x28
		0x41, 0x5B,                               	// pop  r11
		0xC3                                      	// ret
	};

	bool install_decoder_patch(process_t* proc, mapped_view* shbuf) {
		size_t stub_size = sizeof(decoder_hook);

		uintptr_t hook_addr = (uintptr_t)rvm64::process::memory::allocate_remote_2GB_range(proc->handle, PAGE_EXECUTE_READWRITE, proc->address + proc->size, sizeof(decoder_hook));
		if (!hook_addr) {
			printf("[ERR] Could not find suitable address in the remote process for decoder_hook\n");
			return false;
		}
		/*
			TODO: eventually, write pop_rip function (pop rax, ret), and do a proper bounds check for within the range. For now, this should work fine as the process is not that big.
			TODO:
			decoder hook:
				- save vmcs pointer to mapped_view
				- signal to superv to read state of regs, stack, etc.
				- wait for superv to clear signal and user input to continue.
				- call original vm_decode 
		*/
	}
}
#endif // HYPRPATCH_HPP
