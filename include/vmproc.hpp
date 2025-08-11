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

		size_t size = 0;
		size_t read = 0;

		if (!ReadProcessMemory(hprocess, (LPVOID)base, (LPVOID)buffer, head_size, &read) || read != head_size) {
			printf("[ERR] get_process_size: failed to read process memory: 0x%lx\n", GetLastError());
			return 0;
		}

		auto dos_head = (PIMAGE_DOS_HEADER)buffer;
		auto nt_head = (PIMAGE_NT_HEADERS)((UINT8*)(buffer) + dos_head->e_lfanew);

		if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
			return 0;
		}

		auto section = IMAGE_FIRST_SECTION(nt_head);
		for (WORD i = 0; i < nt_head->FileHeader.NumberOfSections; i++, section++) {
			if (strncmp((const char*)section->Name, ".text", 5) == 0) {

				uintptr_t txt_base = (uintptr_t)base + section->VirtualAddress;
				size = txt_base + section->Misc.VirtualSize;
			}
		}

		HeapFree(GetProcessHeap(), 0, buffer);
		return size; 
	}

	bool get_process_id(uintptr_t* ppid, const CHAR* target_name) {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &pe32)) {
			do {
				char entry_name[MAX_PATH];
				x_strcpy(entry_name, pe32.szExeFile, MAX_PATH -1);

				if (x_strcmp(entry_name, target_name) == 0) {
					*ppid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &pe32));
		}

		CloseHandle(snapshot);
		return true;
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

		printf("	process name: %s\n", target_name);

		if (!get_process_id(&proc->id, target_name)) {
			printf("[ERR] Failed to get process id.\n");
			goto defer;
		}

		printf("	process id: %d\n", proc->pid);

		proc->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc->pid);
		if (!proc->handle) {
			printf("[ERR] Failed to get process handle.\n");
			return goto defer;
		}

		printf("	process handle: 0x%lx\n", proc->handle);

		proc->address = (uintptr_t)GetProcAddress((HMODULE)proc->handle, target_name);
		if (!proc->address) {
			printf("[ERR] Failed to get process address.\n");
			goto defer;
		}

		printf("	process address: 0x%llx\n", proc->address);

		if (!get_process_size(proc->handle, proc->address, proc->pid, &proc->size)) {
			printf("[ERR] Failed to get process size.\n");
			goto defer;
		}

		printf("	process size: %d\n", proc->size);

		success = true;
defer:
		if (!success) {
			destroy_process_info(&proc);
		}

		return proc;
	}
}
#endif // HYPRPROC_HPP
