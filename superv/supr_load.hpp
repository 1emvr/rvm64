#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP

// supr_load.hpp or a shared ntwrap.hpp
#ifndef NTWRAP_HPP
#define NTWRAP_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// Must define this BEFORE including Windows headers to get all NT stuff:
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Win7+
#endif

#include <windows.h>
#include <winternl.h>

// Some SDKs declare the enum but not the constant
#ifndef ThreadBasicInformation
#define ThreadBasicInformation (THREADINFOCLASS)0
#endif

#endif
#include <tlhelp32.h>
#include "supr_scan.hpp"
#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmipc.hpp"

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *NtQueryInformationThread_t)(
		_In_ HANDLE ThreadHandle,
		_In_ THREADINFOCLASS ThreadInformationClass,
		_Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
		_In_ ULONG ThreadInformationLength,
		_Out_opt_ PULONG ReturnLength
		);

namespace superv::loader {
	static inline bool is_rw(DWORD prot) {
		const DWORD p = prot & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
		return p == PAGE_READWRITE || p == PAGE_WRITECOPY;
	}

	vmcs_t* get_vmcs(win_process* proc) {
		vmcs_t *vmcs = nullptr;

		auto NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
		if (!NtQueryInformationThread) {
			printf("[ERR] NtQueryInformationThread load failed.\n");
			return nullptr;
		}

		// NOTE: obtain magic
		const uint64_t vm_magic1 = VM_MAGIC1, vm_magic2 = VM_MAGIC2;
		printf("[INF] searching for vm magic: 0x%llx, 0x%llx\n", vm_magic1, vm_magic2);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			printf("[ERR] could not get handle to remote process threads: GetLastError=0x%lx\n", GetLastError());
			return nullptr;
		}

		THREADENTRY32 entry = { };
		entry.dwSize = sizeof(entry);

		if (!Thread32First(snapshot, &entry)) {
			printf("[ERR] could not get list to remote process threads: GetLastError=0x%lx\n", GetLastError());
			CloseHandle(snapshot);
			return nullptr;
		}
		do {
			THREAD_BASIC_INFORMATION tbi = { };
			NT_TIB tib = { };
			SIZE_T read = 0;

			if (entry.th32OwnerProcessID != proc->pid) {
				continue;
			}

			printf("[INF] found entry with PID %d. Opening thread and searching for magic...\n", proc->pid);
			HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
			if (!thread) {
				continue;
			}

			ULONG retlen = 0;
			NTSTATUS status = NtQueryInformationThread(thread, ThreadBasicInformation, &tbi, sizeof(tbi), &retlen);
			if (status < 0 || !tbi.TebBaseAddress) {
				CloseHandle(thread);
				continue;
			}

			if (!ReadProcessMemory(proc->handle, tbi.TebBaseAddress, &tib, sizeof(tib), &read) || read != sizeof(tib)) {
				printf("[ERR] unable to read process thread information block: GetLastError=0x%lx\n", GetLastError());
				CloseHandle(thread);
				continue;
			}

			uint8_t *stacklo = (uint8_t*)tib.StackLimit;
			uint8_t *stackhi = (uint8_t*)tib.StackBase;

			printf("[INF] searching stack for magic: 0x%p - 0x%p\n", stackhi, stacklo);
			for (uint8_t* next = stacklo; next < stackhi; ) {
				MEMORY_BASIC_INFORMATION mbi = { };

				if (!VirtualQueryEx(proc->handle, next, &mbi, sizeof(mbi))) {
					printf("[ERR] unable to query basic memory info: GetLastError=0x%lx\n", GetLastError());
					break;
				}

				uint8_t *region_base = (uint8_t*)MAX((uintptr_t)mbi.BaseAddress, (uintptr_t)stacklo);
				uint8_t *region_end = (uint8_t*)MIN((uintptr_t)mbi.BaseAddress + mbi.RegionSize, (uintptr_t)stackhi);
				size_t region_size = (size_t)(region_end - region_base);

				const bool scan = 
					(mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) && 
					region_size >= sizeof(vmcs_t) && is_rw(mbi.Protect);

				if (scan) {
					uint8_t *buffer = (uint8_t*)VirtualAlloc(nullptr, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (!buffer) {
						printf("[ERR] fatal. could not allocate buffer: GetLastError=0x%lx\n", GetLastError());
						return nullptr;
					}

					read = 0;
					if (ReadProcessMemory(proc->handle, region_base, buffer, region_size, &read) && read >= sizeof(vmcs_t)) {
						for (size_t i = 0; i + sizeof(vmcs_t) <= read; i += sizeof(uintptr_t)) {

							const vmcs_t *scanner = (const vmcs_t*)(buffer + i); // scanner *buffer + offset 
							if (scanner->magic1 != vm_magic1 || scanner->magic2 != vm_magic2) {
								continue;
							}

							vmcs_t check = { }; 
							uintptr_t remote = (uintptr_t)region_base + i; 
							size_t chk_size = (size_t)PROCESS_BUFFER_SIZE;
							size_t chk_read = 0;

							if (!ReadProcessMemory(proc->handle, (LPCVOID)remote, &check, sizeof(check), &chk_read) || chk_read != sizeof(check)) {
								printf("[ERR] cannot read the stack...\n");
								continue;
							}

							auto in_range   	= [&](uint8_t* p){ return p >= stacklo && p + sizeof(vmcs_t) <= stackhi; };
							auto is_aligned 	= [&](uintptr_t p){ return (p & (alignof(vmcs_t) - 1)) == 0; };
							uint8_t *self_ptr 	= (uint8_t*)check.ptrs.self;

							if (!self_ptr || !is_aligned((uintptr_t)self_ptr) || !in_range(self_ptr)) {
								continue;
							}

							chk_read = 0;
							if (!ReadProcessMemory(proc->handle, (LPCVOID)self_ptr, &check, sizeof(check), &chk_read) || chk_read != sizeof(check)) {
								printf("dereferenced self pointer could not be read from... continue.\n");
								continue;
							}
							if (check.magic1 != vm_magic1 || check.magic2 != vm_magic2) {
								printf("!! critical: self pointer points to non-magic values... continue.\n");
								continue;
							}

							if (check.proc.buffer == 0)  			{ printf("[ERR] proc buffer is null\n"); continue; }
							if (check.proc.size != chk_size) 		{ printf("[ERR] proc size did not pass checks: 0x%lx bytes found, expected 0x%lx.\n", check.proc.size, chk_size); continue; }
								
							vmcs = (vmcs_t*)VirtualAlloc(nullptr, sizeof(vmcs_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
							if (!vmcs) {
								printf("[ERR] could not allocate local vmcs buffer: GetLastError=0x%lx\n", GetLastError());
								VirtualFree(buffer, 0, MEM_RELEASE);
								return nullptr;
							}

							memcpy(vmcs, &check, sizeof(check));
							memcpy(&vmcs->thread_id, &entry.th32ThreadID, sizeof(DWORD));

							printf("\tvmcs address =0x%p\n", 	vmcs->ptrs.self); 		
							printf("\tvmcs buffer=0x%p\n", 		vmcs->proc.buffer); 
							printf("\tvmcs buffer size=%d\n", 	vmcs->proc.size); 	

							CloseHandle(thread);
							CloseHandle(snapshot);
							VirtualFree(buffer, 0, MEM_RELEASE);

							return vmcs;
						}
					}
				}
				next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
			}
			CloseHandle(thread);
		} while(Thread32Next(snapshot, &entry));

		CloseHandle(snapshot);
		return nullptr;
	}

	bool remote_write_file(HANDLE hprocess, vmcs_t* vmcs, const char* filepath) {
		LARGE_INTEGER li = {};

		printf("[INF] reading target ELF file.\n");
		HANDLE hfile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);                 
		if (hfile == INVALID_HANDLE_VALUE) {
			printf("[ERR] unable to find target ELF file.\n");
			return false;
		}

		printf("[INF] getting file size...\n");
		if (!GetFileSizeEx(hfile, &li)) {
			printf("[ERR] GetFileSizeEx failed.\n");
			CloseHandle(hfile);
			return false;
		}

		if (li.QuadPart < 0 || (SIZE_T)li.QuadPart > PROCESS_BUFFER_SIZE) {
			printf("[ERR] ELF too large for the vmcs buffer.\n");
			CloseHandle(hfile);
			return false;
		}

		uint64_t total = li.QuadPart, sent = 0; // tracking how much is written
		uint8_t buffer[64 * 1024];

		while (sent < total) {
			DWORD to_read = (DWORD)MIN(sizeof(buffer), total - sent);	
			DWORD read = 0;
			SIZE_T write = 0;

			if (!ReadFile(hfile, buffer, to_read, &read, nullptr)) {
				printf("[ERR] unable to read from file.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}
			if (read == 0) {
				printf("[ERR] unexpected EOF.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}

			uintptr_t remote = vmcs->proc.buffer + sent;
			if (!rvm64::memory::write_process_memory(hprocess, remote, buffer, read, &write)) {
				printf("[ERR] unable to write file to remote process.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}

			sent += read;
		}

		fflush(stdout);
		printf("[INF] wrote %zu bytes to vmcs buffer at 0x%p\n", (size_t)sent, (void*)vmcs->proc.buffer);

		if (!rvm64::ipc::set_vmcs_write_size(hprocess, vmcs, (uint64_t)sent)) {
			printf("[ERR] vmcs write error (write_size).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}
		printf("[INF] writing ELF information to vmcs\n");

 		uint64_t ready = 1;
		if (!rvm64::ipc::set_vmcs_ready(hprocess, vmcs, ready)) {
			printf("[ERR] vmcs write error (ready).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		printf("[INF] ELF loaded into shared memory. VM should be starting now...\n");
		return true; 
	}
}
#endif // HYPRLOAD_HPP
