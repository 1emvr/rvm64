#ifndef HYPRPROC_HPP
#define HYPRPROC_HPP
#include <windows.h>
#include <tlhelp32.h>
#include <string>

#include "../include/vmlib.hpp"

namespace rvm64::process {
	SIZE_T get_process_size(HANDLE hprocess, uintptr_t base) {
		MEMORY_BASIC_INFORMATION mbi;

		UINT_PTR address = base;
		SIZE_T total_size = 0;

		while (VirtualQueryEx(hprocess, (LPCVOID)address, &mbi, sizeof(mbi))) {
			if ((uintptr_t)mbi.AllocationBase != base) {
				break;
			}

			total_size += mbi.RegionSize;
			address += mbi.RegionSize;
		}

		return total_size;
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

				size_t name_len = strlen(entry_name);
				if (name_len > 4 && x_endwith(entry_name, ".exe")) {
					entry_name[name_len - 4] = 0;
				}
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

		proc->pid = get_process_id(target_name);
		if (!proc->pid) {
			goto defer;
		}

		proc->address = get_module_base(proc->pid, target_name);
		if (!proc->address) {
			goto defer;
		}

		proc->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc->pid);
		if (!proc->handle) {
			goto defer;
		}

		proc->size = get_process_size(proc->handle, proc->address);
		if (!proc->size) {
			goto defer;
		}
		success = true;
defer:
		if (!success) {
			destroy_process_info(&proc);
		}

		return proc;
	}
}
#endif // HYPRPROC_HPP
