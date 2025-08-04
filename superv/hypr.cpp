#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

#include "hypr_load.hpp"

#define SHMEM_NAME L"Local\\VMSharedBuffer"

namespace superv::process {
	typedef struct {
		DWORD pid;
		DWORD address;
		SIZE_T size;
		HANDLE handle;
	} process_t;

	namespace memory {
		bool write_proc_memory(HANDLE hprocess, uintptr_t address, const uint8_t *new_bytes, size_t length) {
			DWORD oldprot = 0;

			if (!VirtualProtectEx(hprocess, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldprot)) {
				return false;
			}

			size_t written = 0;
			bool result = WriteProcessMemory(hprocess, (LPVOID)address, new_bytes, length, &written);

			VirtualProtectEx(hprocess, (LPVOID)address, length, oldprot, &oldprot);
			FlushInstructionCache(hprocess, (LPCVOID)address, length);

			return result && written == length;
		}

		bool read_proc_memory(HANDLE hprocess, uintptr_t address, uint8_t *read_bytes, size_t length) {
			size_t read = 0;

			bool result = ReadProcessMemory(hprocess, (LPCVOID)address, (LPVOID)read_bytes, length, &read);
			return result && read == length;
		}
	}


	namespace information {
		size_t get_proc_size(HANDLE hprocess, uintptr_t base) {
			MEMORY_BASIC_INFORMATION mbi;

			size_t total_size = 0;
			uintptr_t address = base;

			while (VirtualQueryEx(hprocess, (LPCVOID)address, &mbi, sizeof(mbi))) {
				if ((uintptr_t)mbi.AllocationBase != base) {
					break;
				}

				total_size += mbi.RegionSize;
				address += mbi.RegionSize;
			}

			return total_size;
		}

		DWORD get_procid(const std::wstring& target_name) {
			DWORD pid = 0;
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (snapshot == INVALID_HANDLE_VALUE) {
				return 0;
			}

			PROCESSENTRY32W pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32W);

			if (Process32FirstW(snapshot, &pe32)) {
				do {
					std::wstring entry_name = pe32.szExeFile;
					if (entry_name.length() > 4 && entry_name.substr(entry_name.length() - 4) == L".exe") {
						entry_name = entry_name.substr(0, entry_name.length() - 4);
					}
					if (_wcsicmp(entry_name.c_str(), target_name.c_str()) == 0) {
						pid = pe32.th32ProcessID;
						break;
					}
				} while (Process32NextW(snapshot, &pe32));
			}

			CloseHandle(snapshot);
			return pid;
		}

		uintptr_t get_module_base(DWORD pid, const TCHAR* target_name) {
			uintptr_t base_address = 0;
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

			if (snapshot == INVALID_HANDLE_VALUE) {
				return 0;
			}

			MODULEENTRY32 me32;
			me32.dwSize = sizeof(MODULEENTRY32);

			if (Module32First(snapshot, &me32)) {
				do {
					if (_tcscmp(me32.szModule, target_name) == 0) {
						base_address = (uintptr_t)me32.modBaseAddr;
						break;
					}
				} while (Module32Next(snapshot, &me32));
			}

			CloseHandle(snapshot);
			return base_address;
		}

		void destroy_process_info(process_t** proc) {
			if (*proc) {
				if ((*proc)->address) {
					HeapFree(GetProcessHeap(), 0, (*proc)->address);
					(*proc)->address = nullptr;
				}
				if ((*proc)->handle) {
					CloseHandle((*proc)->handle);
					(*proc)->handle = 0;
				}
			}

			HeapFree(GetProcessHeap(), 0, *proc);
			*proc = nullptr;
		}

		process_t* get_process_info(std::wstring target_name) {
			bool success = false;
			process_t *proc = (process_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(process_t));
			if (!proc) {
				goto defer;
			}

			proc->pid = superv::process::information::get_procid(target_name);
			if (!proc->pid) {
				goto defer;
			}

			proc->address = superv::process::information::get_module_base(proc->pid, target_name);
			if (!proc->address) {
				goto defer;
			}

			proc->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc->pid);
			if (!proc->handle) {
				goto defer;
			}

			proc->size = superv::process::information::get_proc_size(proc->handle, proc->address);
			if (!proc->size) {
				goto defer;
			}
			success = true;
defer:
			if (!success) {
				superv::process::information::destroy_process_info(&proc);
			}

			return proc;
		}
	}


	namespace scanner {
		bool data_compare(const uint8_t* data, const uint8_t* pattern, const char* mask) {
			for (; *mask; ++mask, ++data, ++pattern) {
				if (*mask == 'x' && *data != *pattern)
					return false;
			}
			return true;
		}

		uintptr_t signature_scan(HANDLE hprocess, uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) {
			std::vector<uint8_t> buffer(size);

			size_t bytes_read = 0;
			size_t pat_length = strlen(mask);

			if (!ReadProcessMemory(hprocess, (LPVOID)base, buffer.data(), size, &bytes_read)) {
				return 0;
			}
			for (size_t i = 0; i <= size - pat_length; ++i) {
				if (data_compare(buffer.data() + i, pattern, mask))
					return base + i;
			}
			return 0;
		}
	}
}


namespace superv {
	typedef struct {
		uintptr_t offset;
		uintptr_t original;
		uintptr_t trampoline;
	} patch_t;

	uint8_t entry_sig[] = {
		0x48, 0x89, 0x05, 0x01, 0x3f, 0x01, 0x00, 					// 0x00: mov     cs:vmcs, rax
		0xe8, 0x3d, 0xfe, 0xff, 0xff,             					// 0x07: call    rvm64::entry::vm_entry(void)
		0x48, 0x8b, 0x05, 0xf5, 0x3e, 0x01, 0x00  					// 0x0c: mov     rax, cs:vmcs
	};
	uint8_t hook_stub[] = {
		0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,               			// 0x00: mov eax, [rip+disp32]
		0x85, 0xC0,                           						// 0x06: test eax, eax
		0x75, 0xF8,                           						// 0x08: jne -8
		0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x0A: mov dword ptr [rip+disp32], 0
		0xC7, 0x05, 0x00, 0x00, 0x00, 0x00,               			// 0x14: mov dword ptr [rip+disp32], imm32
		0x00, 0x00, 0x00, 0x00,                           			// 0x1A: imm32 = original rel32
		0xE9, 0x00, 0x00, 0x00, 0x00                      			// 0x1E: jmp rel32
	};

	patch_t* install_entry_patch(process_t *proc) {
		uintptr_t hook_addr = (uintptr_t)VirtualAllocEx(proc->handle, nullptr, sizeof(hook_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!hook_addr) {
			return nullptr;
		}

		memset(hook_addr, 0, sizeof(hook_stub));
		if (!superv::process::memory::write_proc_memory(proc->handle, hook_addr, hook_stub, sizeof(hook_stub))) {
			return nullptr;
		}

		uintptr_t entry_offset = superv::process::scanner::signature_scan(proc->handle, proc->address, proc->size, entry_sig, "xxxxxxxx????xxxxxxx");
		if (!entry_offset) {
			return nullptr;
		}

		int32_t original_rel = 0;
		if (!superv::process::memory::read_proc_memory(proc->handle, entry_offset + 8 + 1, (const uint8_t*)&original_rel, sizeof(original_rel))) {
			return nullptr;
		}

		uintptr_t original_entry = entry_offset + 8 + 5 + original_rel;
		int32_t hook_offset = (int32_t)(hook_addr - (entry_offset + 8 + 5));

		if (!superv::process::memory::write_proc_memory(proc->handle, entry_offset + 8 + 1, (uint8_t*)&hook_offset, sizeof(hook_offset))) {
			return nullptr;
		}

		patch_t *patch = (patch_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(patch_t));
		patch->offset = entry_offset + 8 + 1;
		patch->original = original_entry;
		patch->trampoline = hook_addr;

		return patch;
	}

	void modify_trampoline(process_t* proc) {
		
	}

	int main(int argc, char** argv) {
		if (argc < 2) {
			printf("Usage: %s <riscv_elf_file>\n", argv[0]);
			return 1;
		}

		std::wstring target_name = "rvm64";
		process_t *proc = superv::process::information::get_process_info(target_name);
		if (!proc) {
			return 1;
		}

		patch_t *patch = install_entry_patch(proc); 
		if (!patch) {
			return 1;
		}

		shared_buffer *shbuf = create_shared_buffer();
		write_shared_buffer(shbuf, argv[1]);
		destroy_shared_buffer(&shbuf);

		printf("VM Should be starting now..\n");
		return 0;
	}
}
