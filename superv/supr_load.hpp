#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h> 

#include "supr_scan.hpp"
#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"
#include "../include/vmipc.hpp"


typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;        // The exit status of the thread or STATUS_PENDING when the thread has not terminated. (GetExitCodeThread)
	PTEB TebBaseAddress;        // The base address of the memory region containing the TEB structure. (NtCurrentTeb)
	CLIENT_ID ClientId;         // The process and thread identifier of the thread.
	KAFFINITY AffinityMask;     // The affinity mask of the thread. (deprecated) (SetThreadAffinityMask)
	KPRIORITY Priority;         // The current priority of the thread. (GetThreadPriority)
	KPRIORITY BasePriority;     // The current base priority of the thread determined by the thread priority and process priority class.
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

	vm_channel* get_channel(win_process* proc) {
		vm_channel *channel = nullptr;

		auto NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
		if (!NtQueryInformationThread) {
			printf("[ERR] NtQueryInformationThread load failed.\n");
			return nullptr;
		}

		const uint64_t vm_magic1 = VM_MAGIC1, vm_magic2 = VM_MAGIC2;
		printf("[INF] searching for vm magic: 0x%llx, 0x%llx\n", vm_magic1, vm_magic2);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			printf("[ERR] could not get handle to remote process threads: GetLastError=0x%lx\n", GetLastError());
			return nullptr;
		}

		THREADENTRY32 entry = { };
		entry.dwSize = sizeof(entry);

		printf("Thread32First\n");
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
					region_size >= sizeof(vm_channel) && is_rw(mbi.Protect);

				if (scan) {
					uint8_t *buffer = (uint8_t*)VirtualAlloc(nullptr, region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
					if (!buffer) {
						printf("[ERR] fatal. could not allocate buffer: GetLastError=0x%lx\n", GetLastError());
						return nullptr;
					}

					read = 0;
					if (ReadProcessMemory(proc->handle, region_base, buffer, region_size, &read) && read >= sizeof(vm_channel)) {
						for (size_t i = 0; i + sizeof(vm_channel) <= read; i += sizeof(uintptr_t)) {

							const vm_channel *scanner = (const vm_channel*)(buffer + i); // scanner *buffer + offset 
							if (scanner->magic1 != vm_magic1 || scanner->magic2 != vm_magic2) {
								continue;
							}

							vm_channel ch_buffer = { }; // empty struct
							uintptr_t remote = (uintptr_t)region_base + i; // real remote addr
																		   //
							size_t chk_size = (size_t)CHANNEL_BUFFER_SIZE;
							size_t chk_read = 0;

							if (!ReadProcessMemory(proc->handle, (LPCVOID)remote, &ch_buffer, sizeof(ch_buffer), &chk_read) || chk_read != sizeof(ch_buffer)) {
								printf("[ERR] cannot read the stack...\n");
								continue;
							}

							auto in_range   	= [&](uint8_t* p){ return p >= stacklo && p + sizeof(vm_channel) <= stackhi; };
							auto is_aligned 	= [&](uintptr_t p){ return (p & (alignof(vm_channel) - 1)) == 0; };
							uint8_t *self_ptr 	= (uint8_t*)ch_buffer.self;

							if (!self_ptr || !is_aligned((uintptr_t)self_ptr) || !in_range(self_ptr)) {
								printf("self pointer was not aligned/in range.. continue.\n");
								continue;
							}

							chk_read = 0;
							if (!ReadProcessMemory(proc->handle, (LPCVOID)self_ptr, &ch_buffer, sizeof(ch_buffer), &chk_read) || chk_read != sizeof(ch_buffer)) {
								printf("dereferenced self pointer could not be read from... continue.\n");
								continue;
							}

							if (ch_buffer.magic1 != vm_magic1 || ch_buffer.magic2 != vm_magic2) {
								printf("!! critical: self pointer points to non-magic values... continue.\n");
								continue;
							}

							if (ch_buffer.view.buffer == 0)  			{ printf("[ERR] view buffer is null\n"); continue; }
							if (ch_buffer.view.size != chk_size) 		{ printf("[ERR] view size did not pass checks: 0x%lx bytes found, expected 0x%lx.\n", ch_buffer.view.size, chk_size); continue; }
								
							channel = (vm_channel*)VirtualAlloc(nullptr, sizeof(vm_channel), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
							if (!channel) {
								printf("[ERR] could not allocate local channel buffer: GetLastError=0x%lx\n", GetLastError());
								VirtualFree(buffer, 0, MEM_RELEASE);
								return nullptr;
							}

							memcpy(channel, &ch_buffer, sizeof(ch_buffer));
							memcpy(&channel->thread_id, &entry.th32ThreadID, sizeof(DWORD));

							printf("\taddress self=0x%p\n", channel->self); 		
							printf("\taddress view buffer=0x%p\n", channel->view.buffer); 
							printf("\taddress view size=0x%p\n", channel->size_ptr); 	
							printf("\taddress view write size=0x%p\n", channel->write_size_ptr); 
							printf("\taddress 'ready'=0x%p\n", channel->ready_ptr);
							printf("\taddress 'error'=0x%p\n\n", channel->error_ptr);

							CloseHandle(thread);
							CloseHandle(snapshot);
							VirtualFree(buffer, 0, MEM_RELEASE);

							return channel;
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

	bool remote_write_file(HANDLE hprocess, vm_channel* channel, const char* filepath) {
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

		if (li.QuadPart < 0 || (SIZE_T)li.QuadPart > CHANNEL_BUFFER_SIZE) {
			printf("[ERR] ELF too large for the channel buffer.\n");
			CloseHandle(hfile);
			return false;
		}

		uint64_t total = li.QuadPart, sent = 0; // tracking how much is written
		uint8_t buffer[64 * 1024];

		uintptr_t ch_buffer = 0;
		size_t ch_read = 0;

		while (sent < total) {
			DWORD to_read = (DWORD)MIN(sizeof(buffer), total - sent);	
			DWORD read = 0;
			SIZE_T write = 0;

			printf("write loop...\n");
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

			uintptr_t remote = channel->view.buffer + sent;
			if (!rvm64::memory::write_process_memory(hprocess, remote, buffer, read, &write)) {
				printf("[ERR] unable to write file to remote process.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}

			sent += read;

			printf("[INF] sent bytes: %zu, total: %zu\n", sent, total);
			fflush(stdout);
		}

		printf("[INF] wrote %zu bytes to channel buffer at 0x%p\n", (size_t)sent, (void*)channel->view.buffer);

 		uint64_t ready = 1;

		// TODO: create superv channel getter/setter (don't accidentally overwrite the stored addresses)
		if (!rvm64::ipc::set_channel_write_size(hprocess, channel, (uint64_t)sent)) {
			printf("[ERR] channel write error (write_size).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}
		printf("[INF] writing ELF information to channel\n");

		// TODO: create set_channel_unready()
		if (!rvm64::ipc::set_channel_ready(hprocess, channel, ready)) {
			printf("[ERR] channel write error (ready).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		printf("[INF] ELF loaded into shared memory. VM should be starting now...\n");
		return true; 
	}
}
#endif // HYPRLOAD_HPP
