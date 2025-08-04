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

	_data uint8_t hook_stub[] = {
		0x8b, 0x05, 0x00, 0x00, 0x00, 0x00,        	// 0x00: mov eax, [rip+disp32]
		0x85, 0xc0,                    				// 0x06: test eax, eax
		0x75, 0xf8,                    				// 0x08: jne spin (-8)
		0xc7, 0x05, 0x00, 0x00, 0x00, 0x00,			// 0x0a: mov dword ptr [rip+disp32], 0
		0x00, 0x00, 0x00, 0x00,        				// 0x10: imm32 (zero)
		0xe9, 0x00, 0x00, 0x00, 0x00,   			// 0x14: jmp rel32 to original vm_entry
	};

	bool install_entry_patch(process_t *proc, uintptr_t signal_addr) {
		size_t stub_size = sizeof(hook_stub);

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
		{
			// modifying the stub: getting rip-displaced address to shmem->signal and vm_entry 
			int32_t rel1 = (int32_t)(signal_addr - (hook_addr + 0x06)); 
			memcpy(&hook_stub[0x02], &rel1, sizeof(rel1));

			int32_t rel2 = (int32_t)(signal_addr - (hook_addr + 0x10));
			memcpy(&hook_stub[0x0c], &rel2, sizeof(rel2));

			int32_t entry_rel = (int32_t)(original_entry - (hook_addr + 0x19));
			memcpy(&hook_stub[0x15], &entry_rel, sizeof(entry_rel));
		}

		if (!superv::process::memory::write_proc_memory(proc->handle, hook_addr, hook_stub, sizeof(hook_stub))) {
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
		0xE8, 0x85, 0x07, 0xFF, 0xFF,               // 0x05: call    rvm64::decoder::vm_decode(uint)
		0x48, 0x8B, 0x05, 0x75, 0x3F, 0x01, 0x00,   // 0x0a: mov     rax, cs:vmcs
	};

	_data uint8_t hook_stub[] = {
		0x50,                                     // push rax
		0xE8, 0x00, 0x00, 0x00, 0x00,             // call rel32 -> debugger_decode
		0x58,                                     // pop rax
		0xE9, 0x00, 0x00, 0x00, 0x00              // jmp rel32 -> vm_decode
	};

	bool install_step_patch(process_t* proc, uintptr_t ready_addr) {
	}
}
#endif // HYPRPATCH_HPP
