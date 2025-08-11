#ifndef HYPRPATCH_HPP
#define HYPRPATCH_HPP
#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmproc.hpp"

#include "supr_scan.hpp"


namespace superv::patch {
	_rdata static const char entry_mask[] = "xxxxxxxx????xxxxxxx";
	_rdata static const uint8_t entry_sig[] = {
		0x48, 0x89, 0x05, 0x01, 0x3f, 0x01, 0x00, 	// 0x00: mov     cs:vmcs, rax
		0xe8, 0x00, 0x00, 0x00, 0x00,             	// 0x07: call    rvm64::entry::vm_entry(void)
		0x48, 0x8b, 0x05, 0xf5, 0x3e, 0x01, 0x00,  	// 0x0c: mov     rax, cs:vmcs
	};

	_rdata static const uint8_t entry_hook[] = {
		0xcc,
		0x0f, 0xb6, 0x05, 0x00, 0x00, 0x00, 0x00,   // 0x00: movzx eax, byte ptr [rip+disp32]
		0x84, 0xc0,                                 // 0x07: test al, al
		0x75, 0xf5,                                 // 0x09: jne -0xb
		0xc6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x0B: mov byte ptr [rip+disp32], 0
		0xe9, 0x00, 0x00, 0x00, 0x00,               // 0x12: jmp rel32
	};

	bool install_entry_hook(win_process *proc, vm_channel* channel) {
		size_t stub_size = sizeof(entry_hook);
		uint8_t buffer[stub_size];

		memcpy(buffer, entry_hook, stub_size);

		printf("[INF] Installing entrypoint hook.\n");
		uintptr_t hook_addr = (uintptr_t)rvm64::memory::allocate_2GB_range(proc->handle, PAGE_READWRITE, proc->address + proc->size, sizeof(entry_hook));
		if (!hook_addr) {
			printf("[ERR] allocate_2GB_range failed to find suitable memory in the remote process.\n");
			return false;
		}

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig, entry_mask);
		if (!sig_offset) {
			printf("[ERR] signature_scan failed to find entry call signature in the remote process.\n");
			return false;
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 7;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] read_proc_memory failed to read memory in the remote process.\n");
			return false;
		}

		uintptr_t ch_signal = (uintptr_t)channel->self + offsetof(vm_channel, ipc.signal);
		uintptr_t original_call = sig_offset + 5 + original_rel;
		{
			int32_t disp32_1 = (int32_t)(ch_signal - (hook_addr + 0x07));
			memcpy(&buffer[0x03], &disp32_1, sizeof(disp32_1));

			int32_t disp32_2 = (int32_t)(ch_signal - (hook_addr + 0x12));
			memcpy(&buffer[0x0D], &disp32_2, sizeof(disp32_2));

			int32_t call_rel = (int32_t)(original_call - (hook_addr + 0x17));
			memcpy(&buffer[0x13], &call_rel, sizeof(call_rel));
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, sizeof(entry_hook))) {
			printf("[ERR] write_proc_memory failed to write entry hook in the remote process.\n");
			return false;
		}

		int32_t hook_offset = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_offset, sizeof(hook_offset))) {
			printf("[ERR] write_proc_memory failed to write entry hook in the remote process.\n");
			return false;
		}

		return true;
	}

	_rdata static const char decoder_mask[] = "xxxxxx????xxxxxxx";
	_rdata static const uint8_t decoder_sig[] = { 
		0x8b, 0x45, 0xfc,										// 0x00: mov     eax, [rbp+opcode]
		0x89, 0xc1,                                 			// 0x03: mov     ecx, eax        ; opcode
		0xe8, 0x00, 0x00, 0x00, 0x00,               			// 0x05: call    rvm64::decoder::vm_decode(uint)
		0x48, 0x8b, 0x05, 0x75, 0x3f, 0x01, 0x00,   			// 0x0a: mov     rax, cs:vmcs
	};

	_rdata static const uint8_t decoder_hook[] = {
		0xcc,
		0x41, 0x53,                               				// 0x00: push r11
		0x4c, 0x8d, 0x1d, 0x00,0x00,0x00,0x00,    				// 0x02: lea  r11, &channel->ipc.opcode (rip+disp32)
		0x41, 0x89, 0x03,                         				// 0x09: mov  dword ptr [r11], eax <-- CHECK THIS
		0x4c, 0x8d, 0x1d, 0x00,0x00,0x00,0x00,    				// 0x0c: lea  r11, &channel->ipc.vmcs (rip+disp32)
		0x49, 0x89, 0x0b,                         				// 0x13: mov  qword ptr [r11], rcx <-- CHECK THIS
		0x4c, 0x8d, 0x1d, 0x00,0x00,0x00,0x00,    				// 0x16: lea  r11, &channel->ipc.signal (rip+disp32)
		0x41, 0x80, 0x3b, 0x00,                   				// 0x1d: cmp  byte ptr [r11], 0
		0x75, 0xfa,                               				// 0x21: jne  -6                  ; spin 
		0x48, 0x83, 0xec, 0x28,                   				// 0x23: sub  rsp, 0x28           ; shadow + align
		0xe8, 0x00, 0x00, 0x00, 0x00,                			// 0x27: call rel32               ; vm_decode
		0x48, 0x83, 0xc4, 0x28,                   				// 0x2c: add  rsp, 0x28
		0x41, 0x5b,                               				// 0x30: pop  r11
		0xc3                                      				// 0x32: ret
	};

	bool install_decoder_hook(win_process* proc, vm_channel* channel) {
		size_t stub_size = sizeof(decoder_hook);
		uint8_t buffer[stub_size];

		memcpy(buffer, decoder_hook, stub_size);

		printf("[INF] Installing decoder hook.\n");
		uintptr_t hook_addr = (uintptr_t)rvm64::memory::allocate_2GB_range(proc->handle, PAGE_READWRITE, proc->address + proc->size, sizeof(decoder_hook));
		if (!hook_addr) {
			printf("[ERR] allocate_2GB_range failed to find suitable memory in the remote process.\n");
			return false;
		}

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, decoder_sig, decoder_mask);
		if (!sig_offset) {
			printf("[ERR] signature_scan failed to find decoder call signature in the remote process.\n");
			return false;
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 5;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] read_proc_memory failed to read memory in the remote process.\n");
			return false;
		}

		uintptr_t original_call = call_site + 5 + original_rel;
		uintptr_t ch_vmcs 		= channel->self + offsetof(vm_channel, vmcs);
		uintptr_t ch_opcode 	= channel->self + offsetof(vm_channel, ipc.opcode);
		uintptr_t ch_signal 	= channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t disp32_1 = (int32_t)(ch_opcode - (hook_addr + 0x09));
			memcpy(&buffer[0x05], &disp32_1, sizeof(disp32_1));

			int32_t disp32_2 = (int32_t)(ch_vmcs - (hook_addr + 0x13));
			memcpy(&buffer[0x0f], &disp32_2, sizeof(disp32_2));

			int32_t disp32_3 = (int32_t)(ch_signal - (hook_addr + 0x1d));
			memcpy(&buffer[0x19], &disp32_3, sizeof(disp32_3));

			int32_t call_rel = (int32_t)(original_call - (hook_addr + 0x33));
			memcpy(&buffer[0x28], &call_rel, sizeof(call_rel));
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, sizeof(decoder_hook))) {
			printf("[ERR] write_proc_memory failed to write decoder hook in the remote process.\n");
			return false;
		}

		int32_t hook_offset = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_offset, sizeof(hook_offset))) {
			printf("[ERR] write_proc_memory failed to write decoder hook in the remote process.\n");
			return false;
		}

		return true;
	}
}
#endif // HYPRPATCH_HPP
