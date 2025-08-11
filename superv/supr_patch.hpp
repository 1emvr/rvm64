#ifndef HYPRPATCH_HPP
#define HYPRPATCH_HPP
#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmproc.hpp"
#include "../include/vmlib.hpp"

#include "supr_scan.hpp"


namespace superv::patch {
	_rdata static const char entry_mask[] = "xxxxxxxx????xxxxxxx";
	_rdata static const uint8_t entry_sig[] = {
		0x48, 0x89, 0x05, 0x01, 0x3f, 0x01, 0x00,     // 0x00: mov     cs:vmcs, rax
		0xe8, 0x00, 0x00, 0x00, 0x00,                 // 0x07: call    rvm64::entry::vm_entry(void)
		0x48, 0x8b, 0x05, 0xf5, 0x3e, 0x01, 0x00,     // 0x0c: mov     rax, cs:vmcs
	};

	_rdata static const uint8_t entry_hook[] = {
		0xcc,										// +0x00  bp for testing
		0x0f, 0xb6, 0x05, 0x00, 0x00, 0x00, 0x00,	// +0x01  disp@+0x04  	(next ip = hook+0x08)
		0x84, 0xc0,                     			// +0x08  test al, al
		0x75, 0xf5,                     			// +0x0a  jne -0xb 		(spins until 0)
		0xc6, 0x05, 0x00, ,0x00, , 0x00,      		// +0x0c  disp@+0x0f  	(next ip = hook+0x13)
		0x48, 0xb8, 0x00, ,0x00, , 0x00, ,0x00, ,   // +0x13  imm64 trampoline
		0xff, 0xe0                      			// +0x1d  jmp rax
	};

	static constexpr size_t EH_OFF_SIGNAL_LOAD_DISP = 0x04;   // write disp32_1
	static constexpr size_t EH_OFF_SIGNAL_CLR_DISP  = 0x0F;   // write disp32_2
	static constexpr size_t EH_OFF_TRAMP_IMM64      = 0x15;   // write imm64
														  //
	bool install_entry_hook(win_process *proc, vm_channel* channel) {
		size_t stub_size = sizeof(entry_hook);
		uint8_t buffer[stub_size];

		printf("[INF] Installing entrypoint hook.\n");
		x_memcpy(buffer, entry_hook, sizeof(entry_hook));

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig, entry_mask);
		if (!sig_offset) { 
			printf("[ERR] Signature_scan failed for entry.\n"); 
			return false; 
		}

		uintptr_t hook_addr = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_addr) { 
			printf("[ERR] install_entry_hook failed to allocate a hook: 0x%lx.\n", GetLastError()); 
			return false; 
		}

		// original call target we’re detouring from
		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 7;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] read_proc_memory failed.\n"); 
			return false;
		}

		uintptr_t original_call = sig_offset + 5 + original_rel;
		uintptr_t ch_signal = (uintptr_t)channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t disp32_1 = (int32_t)(ch_signal - (hook_addr + 0x08)); 
			int32_t disp32_2 = (int32_t)(ch_signal - (hook_addr + 0x12)); 
			uint64_t abs_target = (uint64_t)original_call;

			x_memcpy(&buffer[EH_OFF_SIGNAL_LOAD_DISP], 	&disp32_1, 	sizeof(disp32_1));
			x_memcpy(&buffer[EH_OFF_SIGNAL_CLR_DISP], 	&disp32_2, 	sizeof(disp32_2));
			x_memcpy(&buffer[EH_OFF_TRAMP_IMM64], 		&abs_target, sizeof(abs_target)); // imm64 starts at 0x14
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, stub_size)) {
			printf("[ERR] write_proc_memory failed (entry stub).\n"); 
			return false;
		}

		// keep 5-byte rel32 site patch (space-limited)
		int32_t hook_rel = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_rel, sizeof(hook_rel))) {
			printf("[ERR] write_proc_memory failed (entry patch).\n"); 
			return false;
		}

		return true;
	}

	// ── decoder ────────────────────────────────────────────────────────────────────

	_rdata static const char decoder_mask[] = "xxxxxx????xxxxxxx";
	_rdata static const uint8_t decoder_sig[] = { 
		0x8b, 0x45, 0xfc,                              // 0x00: mov     eax, [rbp+opcode]
		0x89, 0xc1,                                    // 0x03: mov     ecx, eax        ; opcode
		0xe8, 0x00, 0x00, 0x00, 0x00,                  // 0x05: call    rvm64::decoder::vm_decode(uint)
		0x48, 0x8b, 0x05, 0x75, 0x3f, 0x01, 0x00,      // 0x0a: mov     rax, cs:vmcs
	};

	// Tail now: 48 B8 <imm64> ; FF D0   (mov rax, imm64 ; call rax)
	_rdata static const uint8_t decoder_hook[] = {
		0xCC,
		0x41, 0x53,                                     				// 0x00: push r11
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,          				// 0x02: lea  r11, &channel->ipc.opcode (rip+disp32)
		0x41, 0x89, 0x03,                               				// 0x09: mov  dword ptr [r11], eax
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,          				// 0x0C: lea  r11, &channel->vmcs (rip+disp32)
		0x49, 0x89, 0x0B,                               				// 0x13: mov  qword ptr [r11], rcx
		0x4C, 0x8D, 0x1D, 0x00,0x00,0x00,0x00,          				// 0x16: lea  r11, &channel->ipc.signal (rip+disp32)
		0x41, 0x80, 0x3B, 0x00,                         				// 0x1D: cmp  byte ptr [r11], 0
		0x75, 0xFA,                                     				// 0x21: jne  -6   ; spin
		0x48, 0x83, 0xEC, 0x28,                         				// 0x23: sub  rsp, 0x28  ; shadow + align
		0x48, 0xB8, 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// 0x27: mov  rax, imm64  (target = original vm_decode)
		0xFF, 0xD0,                                     				// 0x31: call rax
		0x48, 0x83, 0xC4, 0x28,                         				// 0x33: add  rsp, 0x28
		0x41, 0x5B,                                     				// 0x37: pop  r11
		0xC3,                                           				// 0x39: ret
	};

	bool install_decoder_hook(win_process* proc, vm_channel* channel) {
		uint8_t buffer[sizeof(decoder_hook)];
		memcpy(buffer, decoder_hook, sizeof(decoder_hook));

		printf("[INF] Installing decoder hook.\n");

		uintptr_t hook_addr = (uintptr_t)rvm64::memory::allocate_2GB_range(proc->handle, PAGE_EXECUTE_READWRITE, proc->address + proc->size, sizeof(decoder_hook));
		if (!hook_addr) { 
			printf("[ERR] allocate_2GB_range failed.\n"); 
			return false; 
		}

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, decoder_sig, decoder_mask);
		if (!sig_offset) { 
			printf("[ERR] signature_scan failed for decoder.\n"); 
			return false; 
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 5;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] read_proc_memory failed.\n"); 
			return false;
		}

		uintptr_t original_call = call_site + 5 + original_rel;

		uintptr_t ch_vmcs   = channel->self + offsetof(vm_channel, vmcs);
		uintptr_t ch_opcode = channel->self + offsetof(vm_channel, ipc.opcode);
		uintptr_t ch_signal = channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t disp32_1 = (int32_t)(ch_opcode - (hook_addr + 0x09));
			memcpy(&buffer[0x05], &disp32_1, sizeof(disp32_1));

			int32_t disp32_2 = (int32_t)(ch_vmcs - (hook_addr + 0x13));
			memcpy(&buffer[0x0F], &disp32_2, sizeof(disp32_2));

			int32_t disp32_3 = (int32_t)(ch_signal - (hook_addr + 0x1D));
			memcpy(&buffer[0x19], &disp32_3, sizeof(disp32_3));

			// absolute call target at 0x27: mov rax, imm64
			uint64_t abs_target = (uint64_t)original_call;
			memcpy(&buffer[0x29], &abs_target, sizeof(abs_target)); // imm64 starts at 0x29
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, sizeof(decoder_hook))) {
			printf("[ERR] write_proc_memory failed (decoder stub).\n"); 
			return false;
		}

		// keep site patch as 5-byte rel32 (space constrained)
		int32_t hook_rel = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_rel, sizeof(hook_rel))) {
			printf("[ERR] write_proc_memory failed (decoder patch).\n"); 
			return false;
		}

		return true;
	}
} 
#endif // HYPRPATCH_HPP
