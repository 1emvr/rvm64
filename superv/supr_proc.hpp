#ifndef HYPRPROC_HPP
#define HYPRPROC_HPP
#include <windows.h>
#include <tlhelp32.h>
#include <string>

namespace rvm64::process {
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

		void destroy_process_info(win_process** proc) {
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

		win_process* get_process_info(std::wstring target_name) {
			bool success = false;
			win_process *proc = (win_process*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(win_process));
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
}
#endif // HYPRPROC_HPP
