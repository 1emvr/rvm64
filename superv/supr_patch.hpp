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
		0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0xff, 0xe0 
	};	

	static const uint8_t spin_hook64[] = {
		0x49, 0xba,                          			// mov  r10, imm64
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <imm64 ready_addr>  
		0x41, 0x0f, 0xb6, 0x12,              			// movzx edx, byte ptr [r10]
		0x85, 0xd2,                          			// test   edx, edx 
		0x74, 0xf8,                          			// je     -8  
		0x41, 0xc6, 0x02, 0x00,              			// mov    byte ptr [r10], 0
		0x48, 0xb8,                          			// mov    rax, imm64
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <imm64 tramp_addr> 
		0xff, 0xe0                           			// jmp    rax
	};

	static constexpr size_t SH_OFF_READY_IMM64 = 0x02; // imm64 for &ready (or ready_ptr)
	static constexpr size_t SH_OFF_TRAMP_IMM64 = 0x18; // imm64 for trampoline

	bool install_spin_hook(win_process* proc, vm_channel* channel, uintptr_t* hook, uintptr_t* trampoline) {
		bool success = false;
		static uint8_t buffer[sizeof(spin_hook64)];
		size_t write = 0;

		uintptr_t ch_ready = (uintptr_t)channel->ready_ptr;
		uintptr_t tramp = (uintptr_t)*trampoline;

		x_memcpy(buffer, spin_hook64, sizeof(spin_hook64));
		{
			printf("[INF] patching stub: channel->ready= 0x%p, trampoline= 0x%p\n", ch_ready, tramp);
			x_memcpy(&buffer[SH_OFF_READY_IMM64], &ch_ready, sizeof(uintptr_t));
			x_memcpy(&buffer[SH_OFF_TRAMP_IMM64], &tramp, sizeof(uintptr_t)); 
		}

		printf("[INF] allocating new hook...\n");
		*hook = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, sizeof(spin_hook64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!*hook) {
			printf("[ERR] install_spin_hook failed to allocate in the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		printf("[INF] writing stub to hook...\n");
		if (!rvm64::memory::write_process_memory(proc->handle, *hook, buffer, sizeof(spin_hook64), &write)) {
			printf("[ERR] install_spin_hook failed to write hook: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		FlushInstructionCache(proc->handle, (LPCVOID)*hook, sizeof(spin_hook64));
		success = true;

		printf("[INF] wrote hook to remote process: hook=0x%p, trampoline=0x%p\n", (void*)*hook, (void*)*trampoline);
defer:
		if (!success && *hook) {
			VirtualFreeEx(proc->handle, (LPVOID)*hook, 0, MEM_RELEASE);
		}
		return success;
	}

	bool install_trampoline(HANDLE hprocess, uintptr_t callee, size_t n_prolg, uintptr_t* tramp_out) {
		bool success = false;
		uint8_t *buffer = nullptr;
		uint64_t back_addr = 0;
		uintptr_t trampoline = 0;
		size_t write = 0;

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

		trampoline = (uintptr_t)VirtualAllocEx(hprocess, nullptr, n_prolg + sizeof(jmp_back), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline) {
			printf("[ERR] install_trampoline could not allocate in the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (!rvm64::memory::write_process_memory(hprocess, (uintptr_t)trampoline, buffer, n_prolg + sizeof(jmp_back), &write)) {
			printf("[ERR] install_trampoline could not write to the remote process: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		FlushInstructionCache(hprocess, (LPCVOID)trampoline, n_prolg + sizeof(jmp_back));
		*tramp_out = trampoline;

		printf("[INF] allocate new trampoline=0x%llx\n", trampoline);
		success = true;
defer:
		if (!success && trampoline) {
			VirtualFreeEx(hprocess, (LPVOID)trampoline, 0, MEM_RELEASE);
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
		size_t write = 0;

		printf("[INF] ===== patch callee =====\n");

		if (n_prolg < 12) {
			printf("[ERR] patch_callee: function prologue must be at least 12 bytes\n"); 
			goto defer;
		}

		buffer = (uint8_t*)VirtualAlloc(nullptr, n_prolg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer) {
			printf("[ERR] patch_callee could not allocate it's own buffer: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		memcpy(buffer, jmp_back, sizeof(jmp_back));
		memcpy(buffer + 2, &hook, sizeof(uintptr_t));

 		if (!rvm64::memory::write_process_memory(hprocess, callee, buffer, sizeof(jmp_back), &write)) {
			printf("[ERR] patch_callee could not write to process memory: 0x%lx.\n", GetLastError()); 
			goto defer;
		}

		if (n_prolg > sizeof(jmp_back)) {
			uint32_t n_fill = n_prolg - sizeof(jmp_back);
			memset(buffer, 0x90, n_fill);		

			if (!rvm64::memory::write_process_memory(hprocess, callee + sizeof(jmp_back), buffer, n_fill, &write)) {
				printf("[ERR] patch_callee could not fill nops in the callee (prologue > 12): 0x%lx.", GetLastError());
				goto defer;
			}
		}

		FlushInstructionCache(hprocess, (LPCVOID)callee, n_prolg);
		success = true;

defer:
		if (buffer) {
			VirtualFree(buffer, 0, MEM_RELEASE);
		}
		return success;
	}

	_rdata static const char entry_mask64[] = "xxxxxxxxxx????x????";
	_rdata static const uint8_t entry_sig64[] = {
		0x85, 0xc0,                     // test    eax, eax
		0x0f, 0x95, 0xc0,               // setnz   al
		0x84, 0xc0,                     // test    al, al
		0x75, 0x0c,                     // jnz     short loc_7FF7B36E30CA
		0xe8, 0x42, 0xfd, 0xff, 0xff,   // call    _ZN5rvm645entry7vm_initEv       
		0xe8, 0x39, 0xfe, 0xff, 0xff, 	// call    _ZN5rvm645entry8vm_entryEv
	};

	bool install_entry_hook(win_process *proc, vm_channel* channel) {
		printf("[INF] ====== install entry hook =====\n");
		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig64, entry_mask64);
		if (!sig_offset) { 
			printf("[ERR] Signature_scan failed for entry.\n"); 
			return false; 
		}

		uintptr_t call_site = sig_offset + 0x0e;
		int32_t original_rel = 0;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(int32_t))) {
			printf("[ERR] install_entry_hook failed to get entry reljmp: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t callee = call_site + 5 + original_rel;
		uintptr_t trampoline = 0;
		size_t n_prolg = 18; // I'm not doing automated disasm to find the prologue size. It will be static and I'll have to change it accordingly.
		
		printf("[INF] installing entrypoint trampoline.\n");
		if (!install_trampoline(proc->handle, callee, n_prolg, &trampoline)) {
			printf("[ERR] install_entry_hook failed to install trampoline: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t hook = 0;
		printf("[INF] installing entrypoint spin hook.\n");
		if (!install_spin_hook(proc, channel, &hook, &trampoline)) {
			printf("[ERR] install_entry_hook failed to write a hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		printf("[INF] patching entrypoint call site at 0x%p.\n", call_site);
		if (!patch_callee(proc->handle, callee, hook, n_prolg)) {
			printf("[ERR] install_entry_hook failed to patch prologue: 0x%lx.\n", GetLastError()); 
			return false;
		}

		FlushInstructionCache(proc->handle, (LPCVOID)call_site, 0x5);
		return true;
	}

	_rdata static const char decoder_mask64[] = "xxxxxxxx????";
	_rdata static const uint8_t decoder_sig64[] = { 
		0xff, 0xd0,						// +0x00: call    rax ; __imp_RaiseException
		0x8b, 0x45, 0xfc,				// +0x02: mov     eax, dword ptr [rbp+var_4]
		0x89, 0xc1,                    	// +0x05: mov     ecx, eax                        ; this
		0xe8, 0xe9, 0xf1, 0xfe, 0xff,  	// +0x07: call    _ZN5rvm647decoder9vm_decodeEj   ; rvm64::decoder::vm_decode(uint)
	};

	bool install_decoder_hook(win_process* proc, vm_channel* channel) {
		printf("[INF] ====== install decoder hook =====\n");
		uintptr_t sig_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, decoder_sig64, decoder_mask64);
		if (!sig_offset) { 
			printf("[ERR] signature_scan failed for decoder.\n"); 
			return false; 
		}

		int32_t original_rel = 0;
		uintptr_t call_site = sig_offset + 0x07;

		if (!rvm64::memory::read_process_memory(proc->handle, call_site + 1, (uint8_t*)&original_rel, sizeof(original_rel))) {
			printf("[ERR] install_decoder_hook failed to read process memory: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t callee = call_site + 5 + original_rel;
		uintptr_t trampoline = 0;
		size_t n_prolg = 12;

		printf("[INF] installing decoder trampoline.\n");
		if (!install_trampoline(proc->handle, callee, n_prolg, &trampoline)) {
			printf("[ERR] install_decoder_hook failed to install trampoline: 0x%lx.\n", GetLastError()); 
			return false;
		}

		uintptr_t hook = 0;
		printf("[INF] installing decoder spin hook.\n");
		if (!install_spin_hook(proc, channel, &hook, &trampoline)) {
			printf("[ERR] install_decoder_hook failed to write a hook: 0x%lx.\n", GetLastError()); 
			return false;
		}

		printf("[INF] patching decoder call site at 0x%p.\n", call_site);
		if (!patch_callee(proc->handle, callee, hook, n_prolg)) {
			printf("[ERR] install_decoder_hook failed to patch prologue: 0x%lx.\n", GetLastError()); 
			return false;
		}

		return true;
	}
} 
#endif // HYPRPATCH_HPP
