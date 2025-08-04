#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>


#define SHMEM_NAME L"Local\\VMSharedBuffer"

typedef struct {
    uint8_t* address;
    size_t size;
    volatile int ready;
} shared_buffer;


namespace superv::process {
	namespace memory {
		BOOL patch_proc_memory(HANDLE hprocess, uintptr_t address, const uint8_t *new_bytes, size_t length) {
			DWORD oldprot = 0;

			if (!VirtualProtectEx(hprocess, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldprot)) {
				return false;
			}

			SIZE_T bytes_written = 0;
			BOOL result = WriteProcessMemory(hprocess, (LPVOID)address, new_bytes, length, &bytes_written);

			VirtualProtectEx(hprocess, (LPVOID)address, length, oldprot, &olprot);
			return result && bytes_written == length;
		}
	}

	namespace information {
		VOID destroy_process(process **proc) {
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

		SIZE_T get_proc_size(HANDLE hprocess, uintptr_t base) {
			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T total_size = 0;

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

			if (snapshot != INVALID_HANDLE_VALUE) {
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
			}
			return pid;
		}

		DWORD get_module_base(DWORD pid, const TCHAR* target_name) {
			DWORD base_address = 0;
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

			if (snapshot != INVALID_HANDLE_VALUE) {
				MODULEENTRY32 me32;
				me32.dwSize = sizeof(MODULEENTRY32);

				if (Module32First(snapshot, &me32)) {
					do {
						if (_tcscmp(me32.szModule, target_name) == 0) {
							base_address = (DWORD)me32.modBaseAddr;
							break;
						}
					} while (Module32Next(snapshot, &moduleEntry));
				}
				CloseHandle(snapshot);
			}
			return base_address;
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
			size_t bytes_read  = 0;

			if (!ReadProcessMemory(hprocess, (LPVOID)base, buffer.data(), size, &bytes_read)) {
				return 0;
			}

			size_t pat_length = strlen(mask);
			for (size_t i = 0; i <= size - pat_length; ++i) {
				if (data_compare(buffer.data() + i, pattern, mask))
					return base + i;
			}
			return 0;
		}
	}
}


namespace superv::loader {
	bool write_shared_buffer(const char* filepath) {
		HANDLE hmap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(shared_buffer) + 0x100000, SHMEM_NAME);
		if (!hmap) {
			printf("[-] CreateFileMappingW failed: %lu\n", GetLastError());
			return false;
		}

		LPVOID view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
		if (!view) {
			printf("[-] MapViewOfFile failed: %lu\n", GetLastError());
			CloseHandle(hmap);
			return false;
		}

		shared_buffer* shbuf = (shared_buffer*)view;

		FILE* f = fopen(filepath, "rb");
		if (!f) {
			printf("[-] Failed to open file: %s\n", filepath);
			UnmapViewOfFile(view);
			CloseHandle(hmap);
			return false;
		}

		fseek(f, 0, SEEK_END);
		size_t fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		if (fsize > 0x100000) {
			printf("[-] ELF too large\n");
			fclose(f);
			UnmapViewOfFile(view);
			CloseHandle(hmap);
			return false;
		}

		uint8_t* data = (uint8_t*)(shbuf + 1); // right after the shared_buffer struct
		fread(data, 1, fsize, f);
		fclose(f);

		shbuf->address = data;  // VM will memcpy this out
		shbuf->size = fsize;
		shbuf->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		printf("[*] Press ENTER to exit and release shared memory...\n");
		getchar();

		UnmapViewOfFile(view);
		CloseHandle(hmap);
		return true;
	}
}


typedef struct {
	DWORD pid;
	DWORD address;
	SIZE_T size;
	HANDLE handle;
} process;


namespace superv {
	process* get_process_info(std::wstring target_name) {
		bool success = false;
		process *proc = (process*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(process));
		if (!proc) {
			goto defer;
		}

		proc->pid = superv::process::information::get_procid(target_name);
		if (!proc->pid) {
			goto defer;
		}

		proc->address = superv::process::information::get_module_base(pid, target_name);
		if (!proc->address) {
			goto defer;
		}

		proc->handle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, proc->pid);
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
			destroy_process(&proc);
		}

		return proc;
	}
	int main(int argc, char** argv) {
		if (argc < 2) {
			printf("Usage: %s <riscv_elf_file>\n", argv[0]);
			return 1;
		}

		std::wstring target_name = "rvm64";
		process *proc = superv::process::information::get_process_info(target_name);
		if (!proc) {
			return 1;
		}

		uint8_t dummy[] = {
			0x90, 0x90, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90,
			0x48, 0x89, 0xE5, 0x55, 0x48, 0x8B, 0xEC, 0x90
		};
		if (!superv::process::memory::install_hook(proc->handle, proc->address, proc->size, dummy, "xxx")) {
			return 1;
		}

		if (!write_shared_buffer(argv[1])) {
			return 1;
		}

		printf("VM Should be starting now..\n");
		return 0;
	}
}
