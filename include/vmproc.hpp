#ifndef HYPRPROC_HPP
#define HYPRPROC_HPP
#include <windows.h>
#include <tlhelp32.h>
#include <string>

#include "../include/vmlib.hpp"

namespace rvm64::process {
	bool get_process_size(HANDLE hprocess, uintptr_t base, size_t *psize) {
		if (!base) {
			return false;
		}

		IMAGE_DOS_HEADER dos_head;
		SIZE_T read = 0;

		if (!ReadProcessMemory(hprocess, (LPCVOID)base, &dos_head, sizeof(dos_head), &read) || read != sizeof(dos_head)) {
			printf("[ERR] Failed to read DOS header: 0x%lx\n", GetLastError());
			return false;
		}

		if (dos_head.e_magic != IMAGE_DOS_SIGNATURE) {
			printf("[ERR] Invalid DOS signature\n");
			return false;
		}

		IMAGE_NT_HEADERS nt_head;
		uintptr_t head_base = (base + dos_head.e_lfanew);
		if (!ReadProcessMemory(hprocess, (LPCVOID)head_base, &nt_head, sizeof(nt_head), &read) || read != sizeof(nt_head)) {
			printf("[ERR] Failed to read NT header: 0x%lx\n", GetLastError());
			return false;
		}

		if (nt_head.Signature != IMAGE_NT_SIGNATURE) {
			printf("[ERR] Invalid NT signature\n");
			return false;
		}

		*psize = nt_head.OptionalHeader.SizeOfImage;  // loader’s actual committed size
		return true;
	}

	bool get_process_base(DWORD pid, uintptr_t* pbase) {
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (snap == INVALID_HANDLE_VALUE) {
			return false;
		}

		uintptr_t base = 0;
		if (Module32First(snap, &me32)) {
			*pbase = (uintptr_t)me32.modBaseAddr;
		}

		CloseHandle(snap);
		return true;
	}

	bool get_process_id(DWORD* ppid, const CHAR* target_name) {
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (snap == INVALID_HANDLE_VALUE) {
			return false;
		}

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snap, &pe32)) {
			do {
				char entry_name[MAX_PATH];
				x_strcpy(entry_name, pe32.szExeFile, MAX_PATH -1);

				if (x_strcmp(entry_name, target_name) == 0) {
					*ppid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(snap, &pe32));
		}

		CloseHandle(snap);
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

		if (!get_process_id(&proc->pid, target_name)) {
			printf("[ERR] Failed to get process id.\n");
			goto defer;
		}

		printf("	process id: %d\n", proc->pid);

		proc->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc->pid);
		if (!proc->handle) {
			printf("[ERR] Failed to get process handle.\n");
			goto defer;
		}

		printf("	process handle: 0x%lx\n", proc->handle);

		if (!get_process_base(proc->pid, &proc->address)) {
			printf("[ERR] Failed to get process address.\n");
			goto defer;
		}

		printf("	process address: 0x%llx\n", proc->address);

		if (!get_process_size(proc->handle, proc->address, &proc->size)) {
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
