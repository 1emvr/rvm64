#ifndef HYPRPROC_HPP
#define HYPRPROC_HPP
#include <windows.h>
#include <tlhelp32.h>
#include <string>

#include "../include/vmlib.hpp"

namespace rvm64::process {
	SIZE_T get_process_size(HANDLE hprocess, uintptr_t base) {
		if (!base) {
			return 0;
		}
		constexpr size_t head_size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS);
		uint8_t* buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, head_size);
		size_t read = 0;

		if (!ReadProcessMemory(hprocess, base, (LPVOID)buffer, head_size, &read) || read != head_size) {
			printf("[ERR] get_process_size: failed to read process memory: 0x%lx", GetLastError());
			return 0;
		}

		auto dos_head = (PIMAGE_DOS_HEADER)buffer;
		if (dos_head->e_magic != IMAGE_DOS_SIGNATURE) {
			return 0;
		}

		auto nt_head = (PIMAGE_NT_HEADERS)((UINT8*)(buffer) + dos_head->e_lfanew);
		if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
			return 0;
		}

		auto section = IMAGE_FIRST_SECTION(nt_head);
		for (WORD i = 0; i < nt_head->FileHeader.NumberOfSections; i++, section++) {
			if (strncmp((const char*)section->Name, ".text", 5) == 0) {

				uintptr_t txt_base = (uintptr_t)base + section->VirtualAddress;
				return txt_base + section->Misc.VirtualSize;
			}
		}
		return 0; 
	}

	DWORD get_process_id(const CHAR* target_name) {
		DWORD pid = 0;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (snapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &pe32)) {
			do {
				char entry_name[MAX_PATH];
				x_strcpy(entry_name, pe32.szExeFile, MAX_PATH -1);

				if (x_strcmp(entry_name, target_name) == 0) {
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &pe32));
		}

		CloseHandle(snapshot);
		return pid;
	}

	UINT_PTR get_module_base(DWORD pid, const CHAR* target_name) {
		UINT_PTR base_address = 0;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

		if (snapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}

		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(snapshot, &me32)) {
			do {
				if (strcmp(me32.szModule, target_name) == 0) {
					base_address = (uintptr_t)me32.modBaseAddr;
					break;
				}
			} while (Module32Next(snapshot, &me32));
		}

		CloseHandle(snapshot);
		return base_address;
	}

	void destroy_process_info(win_process** proc) {
		if (!proc) {
			return;
		}
		if (*proc) {
			HeapFree(GetProcessHeap(), 0, *proc);
			*proc = nullptr;
		}
	}

	win_process* get_process_info(const CHAR* target_name) {
		bool success = false;
		win_process *proc = (win_process*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(win_process));
		if (!proc) {
			goto defer;
		}

		printf("[INF] Getting target process ID.\n");
		proc->pid = get_process_id(target_name);
		if (!proc->pid) {
			goto defer;
		}

		printf("[INF] Getting target process base adddress.\n");
		proc->address = get_module_base(proc->pid, target_name);
		if (!proc->address) {
			goto defer;
		}

		printf("[INF] Getting target process handle.\n");
		proc->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc->pid);
		if (!proc->handle) {
			goto defer;
		}

		printf("[INF] Getting target process size.\n");
		proc->size = get_process_size(proc->handle, proc->address);
		if (!proc->size) {
			goto defer;
		}

		printf("[INF] Process info success.\n");
		success = true;
defer:
		if (!success) {
			destroy_process_info(&proc);
		}

		printf(R"(
	process name: %s
	process id: %d
	process base: 0x%llx
	process handle: 0x%llx
	process size: 0x%lx)", target_name, proc->pid, proc->address, proc->handle, proc->size);

		return proc;
	}
}
#endif // HYPRPROC_HPP
