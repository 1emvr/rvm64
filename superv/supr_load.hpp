#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "supr_scan.hpp"

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* NtQueryInformationThread_t)(
  [in]            HANDLE          ThreadHandle,
  [in]            THREADINFOCLASS ThreadInformationClass,
  [in, out]       PVOID           ThreadInformation,
  [in]            ULONG           ThreadInformationLength,
  [out, optional] PULONG          ReturnLength
);

namespace superv::loader {
	struct remote_channel {
		vm_channel channel;     
		uintptr_t  remote_addr; 
		DWORD      thread_id;   
	};

	static inline bool is_rw(DWORD prot) {
		const DWORD p = prot & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
		return p == PAGE_READWRITE || p == PAGE_WRITECOPY;
	}

	// TODO: needs refactoring.
	remote_channel* get_channel(win_process* proc) {
		remote_channel *channel = nullptr;

		auto NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
		if (!NtQueryInformationThread) {
			printf("[ERR] NtQueryInformationThread load failed.\n");
			return nullptr;
		}

		const uint64_t vm_magic1 = VM_MAGIC1, vm_magic2 = VM_MAGIC2;
		printf("[INF] searching for vm magic: 0x%llx, 0x%llx\n", vm_magic1, vm_magic2);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			printf("[ERR] could not get handle to remote process threads");
			return nullptr;
		}

		THREADENTRY32 entry = { };
		entry.dwSize = sizeof(entry);

		if (!Thread32First(snapshot, &entry)) {
			CloseHandle(snapshot);
			return nullptr;
		}
		do {
			THREAD_BASIC_INFORMATION tbi = { };
			NT_TIB tib = { };
			SIZE_T read = 0;

			if (entry.th32OwnerProcessId != proc->pid) {
				continue;
			}

			HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
			if (!thread) {
				continue;
			}

			NTSTATUS status = NtQueryInformationThread(thread, 0, &tbi, sizeof(tbi), (PULONG)&read);
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

			for (uint8_t* next = stacklo; next < stackhi; ) {
				MEMORY_BASIC_INFORMATION mbi = { };
				if (!VirtualQueryEx(proc->handle, next, &mbi, sizeof(mbi))) {
					break;
				}

				uint8_t *region_base = (uint8_t*)MAX((uintptr_t)mbi.BaseAddress, (uintptr_t)stacklo);
				uint8_t *region_end = (uint8_t*)MIN((uintptr_t)mbi.BaseAddress + mbi.RegionSize, (uintptr_t)stackhi);
				size_t region_size = (size_t)(region_end - region_base);

				const bool scan = 
					(mbi.State == MEM_COMMIT) && 
					(mbi.Type == MEM_PRIVATE) && 
					region_size >= sizeof(vm_channel) &&
					is_rw(mbi.Protect);

				if (scan) {
					read = 0;
					std::vector<uint8_t> buffer(region_size);

					if (!region_base) {
						continue;
					}
					if (ReadProcessMemory(proc->handle, region_base, buffer.data(), buffer.size(), &read) && read >= sizeof(vm_channel)) {
						vm_channel ch_buffer = { };

						for (size_t i = 0; i + sizeof(vm_channel) <= read; i += sizeof(uintptr_t)) {
							vm_channel *scanner = (vm_channel*)buffer.data() + i;
							if (scanner->magic1 != vm_magic1 || scanner->magic2 != vm_magic2) {
								continue;
							}

							uintptr_t remote = region_base + i;
							read = 0;

							if (!ReadProcessMemory(proc->handle, (LPCVOID)remote, &ch_buffer, sizeof(ch_buffer), &read) || read != sizeof(ch_buffer)) {
								continue;
							}

							size_t check_size = (size_t)BUFFER_CHANNEL_SIZE;

							if (ch_buffer.self != remote) 			continue;
							if (ch_buffer.view.size != check_size) 	continue;
							if (ch_buffer.view.buffer == 0)  		continue;
							if (ch_buffer.ready == 0) 				continue; // vm channel creation must signal "ready"
								
							channel = VirtualAlloc(nullptr, sizeof(remote_channel), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
							if (!channel) {
								printf("[ERR] could not allocate local channel buffer: GetLastError=0x%lx\n", GetLastError());
								return nullptr
							}

							memcpy(&channel->channel, &ch_buffer, sizeof(ch_buffer));
							memcpy(&channel->remote_addr, &remote, sizeof(remote));
							memcpy(&channel->thread_id, &entry.th32ThreadID, sizeof(DWORD));

							printf("\tmagic 1=0x%llx\n", channel->magic1);
							printf("\tmagic 2=0x%llx\n", channel->magic2);
							printf("\taddress self=0x%llx\n", channel->self); 		
							printf("\taddress view buffer=0x%llx\n", channel->view.buffer); 

							printf("\taddress view size=0x%llx\n", channel->view.size); 	
							printf("\taddress view write size=0x%llx\n", channel.view.write_size); 
							printf("\taddress 'ready'=0x%llx\n", channel->ready);
							printf("\taddress 'error'=0x%llx\n\n", channel->error);

							CloseHandle(thread);
							CloseHandle(snapshot);

							return channel;
						}
					}
					next = (uint8_t*)mbi.BaseAddress + (uint8_t*)mbi.RegionSize;
				}
			}
			CloseHandle(thread);
		} while(Thread32Next(snapshot, &entry));

		CloseHandle(thread);
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

		SIZE_T total = li.QuadPart, sent = 0; // tracking how much is written
		BYTE buffer[64 * 1024];

		uintptr_t ch_buffer = 0;
		size_t ch_read = 0;

		printf("[INF] getting real address for channel buffer from address 0x%llx\n", channel->view.buffer);

		if (!ReadProcessMemory(hprocess, (LPCVOID)channel->view.buffer, &ch_buffer, sizeof(uintptr_t), &ch_read) || ch_read != sizeof(uintptr_t)) {
			printf("[ERR] unable to get buffer address from the remote channel: GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		printf("[INF] writing to real channel buffer=0x%llx\n", ch_buffer);
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
			LPVOID remote = (LPVOID)(ch_buffer + sent);
			printf("attempting to write to 0x%llx...\n", remote);

			if (!WriteProcessMemory(hprocess, remote, buffer, read, &write) || write != read) {
				printf("[ERR] unable to write file to remote process.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}

			sent += read;
		}

		printf("[INF] wrote %d bytes to channel buffer at 0x%llx\n", sent, *(uintptr_t*)channel->view.buffer);

 		SIZE_T write = 0;
		if (!WriteProcessMemory(hprocess, (LPVOID)channel->view.write_size, (LPCVOID)&total, sizeof(SIZE_T), &write) || write != sizeof(SIZE_T)) {
			printf("[ERR] channel write error (write_size).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}
		printf("[INF] writing ELF information to channel\n");

		INT32 ready = 1;
		if (!WriteProcessMemory(hprocess, (LPVOID)channel->ready, (LPCVOID)&ready, sizeof(INT32), &write) || write != sizeof(INT32)) {
			printf("[ERR] channel write error (ready).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		printf("[INF] ELF loaded into shared memory\n");
		return true; 
	}
}
#endif // HYPRLOAD_HPP
