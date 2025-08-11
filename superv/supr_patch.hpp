#ifndef HYPRPATCH_HPP
#define HYPRPATCH_HPP
#include <windows.h>

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmproc.hpp"
#include "../include/vmlib.hpp"

#include "supr_scan.hpp"

namespace superv::patch {
	_rdata static const uint8_t jmp_back[12] = { 
		0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xff,0xe0 
	};	

	_rdata static const char entry_mask[] = "xxxxxxxx????xxxxxxx";
	_rdata static const uint8_t entry_sig[] = {
		0x48, 0x89, 0x05, 0x01, 0x3f, 0x01, 0x00,     // +0x00: mov     cs:vmcs, rax
		0xe8, 0x00, 0x00, 0x00, 0x00,                 // +0x07: call    rvm64::entry::vm_entry(void)
		0x48, 0x8b, 0x05, 0xf5, 0x3e, 0x01, 0x00,     // +0x0c: mov     rax, cs:vmcs
	};

	_rdata static const uint8_t entry_hook[] = {
		0xcc,                                   					// +0x00: int3
		0x0f,0xb6,0x05, 0x00, 0x00, 0x00, 0x00,                		// +0x01: movzx eax, byte ptr [rip+disp32]
		0x84,0xc0,                              					// +0x08: test al, al
		0x75,0xf5,                              					// +0x0a: jne 0x01
		0xc6,0x05, 0x00, 0x00, 0x00, 0x00, 0x00,               		// +0x0c: mov byte ptr [rip+disp32], 0
		0x48,0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// +0x13: mov rax, imm64
		0xff,0xe0                               					// +0x1d: jmp rax
	};

	static constexpr size_t EH_OFF_SIGNAL_LOAD_DISP = 0x04; // next IP = hook+0x08
	static constexpr size_t EH_OFF_SIGNAL_CLR_DISP  = 0x0F; // next IP = hook+0x13
	static constexpr size_t EH_OFF_RESUME_IMM64     = 0x15; // imm64 at +0x15
														  
	bool make_trampoline(HANDLE hprocess, uintptr_t callee, size_t n_prolg, uintptr_t* tramp_out) {
		uint8_t *buffer = (uint8_t*)VirtualAlloc(nullptr, n_prolg + sizeof(jmp_back), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!rvm64::memory::read_process_memory(hprocess, callee, buffer, n_prolg)) {
			printf("[ERR] make_trampoline could not read from the remote process: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uint64_t back_addr = (uint64_t)(callee + n_prolg);
		memcpy(buffer + n_prolg, jmp_back, sizeof(jmp_back));
		memcpy(buffer + n_prolg + 2, &back_addr, sizeof(uint64_t));

		void *trampoline = VirtualAllocEx(hprocess, nullptr, n_prolg + sizeof(jmp_back), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline) {
			printf("[ERR] make_trampoline could not allocate in the remote process: 0x%lx.\n", GetLastError()); 
			return false;
		}
		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)trampoline, buffer, n_pro)) {
			printf("[ERR] make_trampoline could not write to the remote process: 0x%lx.\n", GetLastError()); 
			return false;
		}

		FlushInstructionCache(hprocess, trampoline, n_pro);

		*tramp_out = trampoline;
		return true;
	}

	bool patch_callee(HANDLE hprocess, uintptr_t callee, uintptr_t hook, size_t n_prolg) {
		
	}

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

		uintptr_t call_site = sig_offset + 7;
		int32_t original_rel = 0;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] install_entry_hook::read_proc_memory failed: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t original_call = sig_offset + 5 + original_rel;
		uintptr_t hook_addr = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_addr) { 
			printf("[ERR] install_entry_hook failed to allocate a hook: 0x%lx.\n", GetLastError()); 
			return false; 
		}

		uintptr_t ch_signal = (uintptr_t)channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t disp32_1 = (int32_t)(ch_signal - (hook_addr + 0x08)); 
			int32_t disp32_2 = (int32_t)(ch_signal - (hook_addr + 0x13)); 
			uint64_t abs_target = (uint64_t)original_call;

			x_memcpy(&buffer[EH_OFF_SIGNAL_LOAD_DISP], 	&disp32_1, 	sizeof(disp32_1));
			x_memcpy(&buffer[EH_OFF_SIGNAL_CLR_DISP], 	&disp32_2, 	sizeof(disp32_2));
			x_memcpy(&buffer[EH_OFF_RESUME_IMM64], 		&abs_target, sizeof(abs_target)); // imm64 starts at 0x14
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, stub_size)) {
			printf("[ERR] install_entry_hook::write_proc_memory failed to write hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		int32_t hook_rel = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_rel, sizeof(hook_rel))) {
			printf("[ERR] install_entry_hook::write_proc_memory failed to patch vm_entry: 0x%lx.\n", GetLastError()); 
			return false;
		}

		return true;
	}

	// ── decoder ────────────────────────────────────────────────────────────────────

	_rdata static const char decoder_mask[] = "xxxxxx????xxxxxxx";
	_rdata static const uint8_t decoder_sig[] = { 
		0x8b, 0x45, 0xfc,                              // +0x00: mov     eax, [rbp+opcode]
		0x89, 0xc1,                                    // +0x03: mov     ecx, eax        ; opcode
		0xe8, 0x00, 0x00, 0x00, 0x00,                  // +0x05: call    rvm64::decoder::vm_decode(uint)
		0x48, 0x8b, 0x05, 0x75, 0x3f, 0x01, 0x00,      // +0x0a: mov     rax, cs:vmcs
	};

	_rdata static const uint8_t decoder_hook[] = {
		0xcc,                                   					// +0x00: int3
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                	// +0x01: lea r11, [rip+disp32]
		0x41, 0x89, 0x03,                         					// +0x08: mov dword ptr [r11], eax
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                 	// +0x0b: lea r11, [rip+disp32]
		0x49, 0x89, 0x0b,                         					// +0x12: mov qword ptr [r11], rcx
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                	// +0x15: lea r11, [rip+disp32]
		0x41, 0x80, 0x3b, 0x00,                    					// +0x1c: cmp byte ptr [r11], 0
		0x75, 0xfa,                              					// +0x20: jne 0x1c
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// +0x22: mov rax, imm64
		0xff, 0xe0                               					// +0x2c: jmp rax
	};

	static constexpr size_t DH_OFF_OPCODE_DISP = 0x06;
	static constexpr size_t DH_OFF_VMCS_DISP   = 0x10;
	static constexpr size_t DH_OFF_SIGNAL_DISP = 0x1A;
	static constexpr size_t DH_OFF_TRAMP_IMM64 = 0x2A;

	bool install_decoder_hook(win_process* proc, vm_channel* channel) {
		size_t stub_size = sizeof(decoder_hook);
		uint8_t buffer[stub_size];

		printf("[INF] Installing decoder hook.\n");
		memcpy(buffer, decoder_hook, sizeof(decoder_hook));

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, decoder_sig, decoder_mask);
		if (!sig_offset) { 
			printf("[ERR] signature_scan failed for decoder.\n"); 
			return false; 
		}

		uintptr_t hook_addr = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_addr) { 
			printf("[ERR] install_decoder_hook failed to allocate a hook: 0x%lx.\n", GetLastError()); 
			return false; 
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 5;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] install_decoder_hook::read_proc_memory failed: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t original_call = call_site + 5 + original_rel;

		uintptr_t ch_vmcs   = channel->self + offsetof(vm_channel, vmcs);
		uintptr_t ch_opcode = channel->self + offsetof(vm_channel, ipc.opcode);
		uintptr_t ch_signal = channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t disp32_1 = (int32_t)(ch_opcode - (hook_addr + 0x0a));
			memcpy(&buffer[DH_OFFSET_OPCODE_DISP], &disp32_1, sizeof(disp32_1));

			int32_t disp32_2 = (int32_t)(ch_vmcs - (hook_addr + 0x14));
			memcpy(&buffer[DH_OFF_VMCS_DISP], &disp32_2, sizeof(disp32_2));

			int32_t disp32_3 = (int32_t)(ch_signal - (hook_addr + 0x1e));
			memcpy(&buffer[DH_OFFSET_SIGNAL_DISP], &disp32_3, sizeof(disp32_3));

			uint64_t abs_target = (uint64_t)original_call;
			memcpy(&buffer[DH_OFFSET_TRAMP_IMM64], &abs_target, sizeof(abs_target)); 
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook_addr, buffer, sizeof(decoder_hook))) {
			printf("[ERR] install_decoder_hook::write_proc_memory failed to write the hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		int32_t hook_rel = (int32_t)(hook_addr - (call_site + 5));
		if (!rvm64::memory::write_process_memory(proc->handle, call_site + 1, (uint8_t*)&hook_rel, sizeof(hook_rel))) {
			printf("[ERR] install_decoder_hook::write_proc_memory failed to patch decoder: 0x%lx.\n", GetLastError()); 
			return false;
		}

		return true;
	}
} 
#endif // HYPRPATCH_HPP
