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

	bool install_trampoline(HANDLE hprocess, uintptr_t callee, size_t n_prolg, uintptr_t* tramp_out) {
		bool success = false;
		void *trampoline = nullptr;
		uint8_t *buffer = nullptr;
		uint64_t back_addr = 0;

		if (n_prolg < 12) {
			printf("[ERR] install_trampoline: function prologue must be at least 12 bytes\n"); 
			goto defer;
		}

		buffer = (uint8_t*)VirtualAlloc(nullptr, n_prolg + sizeof(jmp_back), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer) {
			printf("[ERR] install_trampoline could not allocate it's own buffer: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (!rvm64::memory::read_process_memory(hprocess, callee, buffer, n_prolg)) {
			printf("[ERR] install_trampoline could not read from the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		back_addr = (uint64_t)(callee + n_prolg);

		memcpy(buffer + n_prolg, jmp_back, sizeof(jmp_back));
		memcpy(buffer + n_prolg + 2, &back_addr, sizeof(uint64_t));

		if (!(trampoline = VirtualAllocEx(hprocess, nullptr, n_prolg + sizeof(jmp_back), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
			printf("[ERR] install_trampoline could not allocate in the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)trampoline, buffer, n_prolg + sizeof(jmp_back))) {
			printf("[ERR] install_trampoline could not write to the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		FlushInstructionCache(hprocess, trampoline, n_prolg + sizeof(jmp_back));
		*tramp_out = (uintptr_t)trampoline;
		success = true;

defer:
		if (!success && trampoline) {
			VirtualFree(trampoline, 0, MEM_RELEASE);
		}
		if (buffer) {
			VirtualFree(buffer, 0, MEM_RELEASE);
		}

		return success;
	}

	// NOTE: prologues with relative addressing or short branches will need to be fixed up. (not supported)
	bool patch_callee(HANDLE hprocess, uintptr_t callee, uintptr_t hook, size_t n_prolg) {
		bool success = false;
		uint8_t *buffer = nullptr;
		DWORD old_prot = 0;	

		if (n_prolg < 12) {
			printf("[ERR] patch_callee: function prologue must be at least 12 bytes\n"); 
			goto defer;
		}

		buffer = (uint8_t*)VirtualAlloc(nullptr, n_prolg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer) {
			printf("[ERR] patch_callee could not allocate it's own buffer: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (!VirtualProtectEx(hprocess, (LPVOID)callee, n_prolg, PAGE_EXECUTE_READWRITE, &old_prot)) {
			printf("[ERR] patch_callee could not change page protections: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		memcpy(buffer, jmp_back, sizeof(jmp_back));
		memcpy(buffer + 2, (LPVOID)&hook, sizeof(uintptr_t));

 		if (!rvm64::memory::write_process_memory(hprocess, callee, buffer, sizeof(jmp_back))) {
			printf("[ERR] patch_callee could not write to process memory: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (n_prolg > sizeof(jmp_back)) {
			uint32_t n_fill = n_prolg - sizeof(jmp_back);
			memset(buffer, 0x90, n_fill);		

			if (!rvm64::memory::write_process_memory(hprocess, callee + sizeof(jmp_back), buffer, n_fill)) {
				printf("[ERR] patch_callee could not fill nops in the callee (prologue > 12): 0x%lx.", GetLastError());
				goto defer;
			}
		}

		VirtualProtectEx(hprocess, (LPVOID)callee, n_prolg, old_prot, &old_prot);
		FlushInstructionCache(hprocess, (LPCVOID)callee, n_prolg);
		success = true;

defer:
		if (buffer) {
			VirtualFree(buffer, 0, MEM_RELEASE);
		}
		return success;
	}

	_rdata static const char entry_mask[] = "xxxxxxxx????x????";
	_rdata static const uint8_t entry_sig[] = {
		0x0F, 0x95, 0xC0,   					// +0x00: setnz   al
		0x84, 0xC0,                             // +0x03: test    al, al
		0x75, 0x0C,                     		// +0x05: jnz     short loc_7FF7FBE03461
		0xE8, 0x01, 0xFD, 0xFF, 0xFF,     		// +0x07: call    _ZN5rvm645entry7vm_initEv       ; rvm64::entry::vm_init(void)
		0xE8, 0x26, 0xFE, 0xFF, 0xFF, 			// +0x0c: call    _ZN5rvm645entry8vm_entryEv      ; rvm64::entry::vm_entry(void)
												// +0x11: ...
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
	static constexpr size_t EH_OFF_SIGNAL_CLR_DISP  = 0x0e; // next IP = hook+0x13
	static constexpr size_t EH_OFF_RESUME_IMM64     = 0x15; // imm64 at +0x15
														  
	bool install_entry_hook(win_process *proc, vm_channel* channel) {
		printf("[INF] Installing entrypoint hook.\n");

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig, entry_mask);
		if (!sig_offset) { 
			printf("[ERR] Signature_scan failed for entry.\n"); 
			return false; 
		}

		uintptr_t call_site = sig_offset + 0x0c;
		int32_t original_rel = 0;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(int32_t))) {
			printf("[ERR] install_entry_hook::read_proc_memory failed to get entry reljmp: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t callee = sig_offset + 5 + original_rel;
		uintptr_t trampoline = 0;
		size_t n_prolg = 12; // I'm not doing automated disasm to find the prologue size. It will be static and I'll have to change it accordingly.
		
		if (!install_trampoline(proc->handle, callee, n_prolg, &trampoline)) {
			printf("[ERR] install_entry_hook::install_trampoline failed: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t hook = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, sizeof(entry_hook), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook) {
			printf("[ERR] install_entry_hook failed to allocate a hook in the remote process: 0x%lx.\n", GetLastError()); 
			return false;
		}

		size_t stub_size = sizeof(entry_hook);
		uint8_t buffer[stub_size];

		x_memcpy(buffer, entry_hook, sizeof(entry_hook));
		uintptr_t ch_signal = (uintptr_t)channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t d32_sgn_load = (int32_t)(ch_signal - (hook + 0x08)); 
			int32_t d32_sgn_clear = (int32_t)(ch_signal - (hook + 0x13)); 

			x_memcpy(&buffer[EH_OFF_SIGNAL_LOAD_DISP], 	&d32_sgn_load, 	sizeof(int32_t));
			x_memcpy(&buffer[EH_OFF_SIGNAL_CLR_DISP], 	&d32_sgn_clear, sizeof(int32_t));
			x_memcpy(&buffer[EH_OFF_RESUME_IMM64], 		&trampoline, 	sizeof(uintptr_t)); // imm64 starts at 0x14
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook, buffer, stub_size)) {
			printf("[ERR] install_entry_hook::write_proc_memory failed to write hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		FlushInstructionCache(proc->handle, (LPCVOID)hook, stub_size);
		if (!patch_callee(proc->handle, callee, hook, n_prolg)) {
			printf("[ERR] install_entry_hook::patch_callee failed to patch prologue: 0x%lx.\n", GetLastError()); 
			return false;
		}

		return true;
	}

	_rdata static const char decoder_mask[] = "xxxxxxxx????";
	_rdata static const uint8_t decoder_sig[] = { 
		0xFF, 0xD0,						// +0x00: call    rax ; __imp_RaiseException
		0x8B, 0x45, 0xFC,				// +0x02: mov     eax, dword ptr [rbp+var_4]
		0x89, 0xC1,                    	// +0x05: mov     ecx, eax                        ; this
		0xE8, 0xE9, 0xF1, 0xFE, 0xFF,  	// +0x07: call    _ZN5rvm647decoder9vm_decodeEj   ; rvm64::decoder::vm_decode(uint)
										// +0x0c: ...
	};

	_rdata static const uint8_t decoder_hook[] = {
		0xcc,                                   					// +0x00: int3
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                	// +0x01: lea r11, [rip+disp32] (opcode)
		0x41, 0x89, 0x03,                         					// +0x08: mov dword ptr [r11], eax 
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                 	// +0x0b: lea r11, [rip+disp32] (vmcs)
		0x49, 0x89, 0x0b,                         					// +0x12: mov qword ptr [r11], rcx 
		0x4c, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,                	// +0x15: lea r11, [rip+disp32] (signal)
		0x41, 0x80, 0x3b, 0x00,                    					// +0x1c: cmp byte ptr [r11], 0
		0x75, 0xfa,                              					// +0x20: jne 0x1c
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// +0x22: mov rax, imm64
		0xff, 0xe0                               					// +0x2c: jmp rax
	};

	static constexpr size_t DH_OFF_OPCODE_DISP = 0x04;
	static constexpr size_t DH_OFF_VMCS_DISP   = 0x0e;
	static constexpr size_t DH_OFF_SIGNAL_DISP = 0x18;
	static constexpr size_t DH_OFF_TRAMP_IMM64 = 0x24;

	bool install_decoder_hook(win_process* proc, vm_channel* channel) {
		printf("[INF] Installing decoder hook.\n");

		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, decoder_sig, decoder_mask);
		if (!sig_offset) { 
			printf("[ERR] signature_scan failed for decoder.\n"); 
			return false; 
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 5;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] install_decoder_hook::read_proc_memory failed: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t callee = call_site + 5 + original_rel;
		uintptr_t trampoline = 0;
		size_t n_prolg = 12;

		if (!install_trampoline(proc->handle, callee, n_prolg, &trampoline)) {
			printf("[ERR] install_decoder_hook::install_trampoline failed: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t hook = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, sizeof(decoder_hook), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook) { 
			printf("[ERR] install_decoder_hook failed to allocate a hook: 0x%lx.\n", GetLastError()); 
			return false; 
		}

		size_t stub_size = sizeof(decoder_hook);
		uint8_t buffer[stub_size];

		memcpy(buffer, decoder_hook, stub_size);
		uintptr_t ch_vmcs   = channel->self + offsetof(vm_channel, vmcs);
		uintptr_t ch_opcode = channel->self + offsetof(vm_channel, ipc.opcode);
		uintptr_t ch_signal = channel->self + offsetof(vm_channel, ipc.signal);
		{
			int32_t d32_opcode = (int32_t)(ch_opcode - (hook + 0x08));
			int32_t d32_vmcs = (int32_t)(ch_vmcs - (hook + 0x12));
			int32_t d32_signal = (int32_t)(ch_signal - (hook + 0x1c));

			memcpy(&buffer[DH_OFF_OPCODE_DISP], &d32_opcode, sizeof(int32_t));
			memcpy(&buffer[DH_OFF_VMCS_DISP], &d32_vmcs, sizeof(int32_t));
			memcpy(&buffer[DH_OFF_SIGNAL_DISP], &d32_signal, sizeof(int32_t));
			memcpy(&buffer[DH_OFF_TRAMP_IMM64], &trampoline, sizeof(uintptr_t)); 
		}

		if (!rvm64::memory::write_process_memory(proc->handle, hook, buffer, sizeof(decoder_hook))) {
			printf("[ERR] install_decoder_hook::write_proc_memory failed to write the hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		FlushInstructionCache(proc->handle, (LPCVOID)hook, stub_size);
		if (!patch_callee(proc->handle, callee, hook, n_prolg)) {
			printf("[ERR] install_decoder_hook::patch_callee failed to patch prologue: 0x%lx.\n", GetLastError()); 
			return false;
		}

		return true;
	}
} 
#endif // HYPRPATCH_HPP
