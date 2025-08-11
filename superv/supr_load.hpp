#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "supr_scan.hpp"

#include "../include/vmmain.hpp"
#include "../include/vmmem.hpp"

namespace superv::loader {
	vm_channel* get_channel(win_process* proc) {
 		static constexpr int64_t vm_magic[2] = { (int64_t)VM_MAGIC1, (int64_t)VM_MAGIC2 }; 

		printf("[INF] Searching for vm magic.\n");
		uintptr_t ch_offset = superv::scanner::signature_scan(proc->handle, proc->address, proc->size, (const uint8_t*)vm_magic, "xxxxxxxxxxxxxxxx");
		if (!ch_offset) {
			printf("[ERR] Could not find the remote vm-channel\n");
			return nullptr;
		}

		printf("[INF] Creating new channel...\n");
		vm_channel *channel = (vm_channel*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		if (!channel) {
			printf("[ERR] Could not create a local vm-channel\n");
			return nullptr;
		}

		if (!rvm64::memory::read_process_memory(proc->handle, ch_offset, (uint8_t*)channel, sizeof(vm_channel))) {
			printf("[ERR] Could not read the remote vm-channel\n");
			HeapFree(GetProcessHeap(), 0, channel);
			return nullptr;
		}

		channel->view.buffer 		= (uint64_t)ch_offset + offsetof(vm_channel, view.buffer); 									
		channel->view.size 			= (uint64_t)ch_offset + offsetof(vm_channel, view.size); 							
		channel->view.write_size 	= (uint64_t)ch_offset + offsetof(vm_channel, view.write_size); 						
											 
		channel->ipc.opcode = (uint64_t)ch_offset + offsetof(vm_channel, ipc.opcode);							
		channel->ipc.signal = (uint64_t)ch_offset + offsetof(vm_channel, ipc.signal);						
																			
		channel->ready = (uint64_t)ch_offset + offsetof(vm_channel, ready); 					
		channel->error = (uint64_t)ch_offset + offsetof(vm_channel, error); 					

		printf("[INF] Channel success!\n");
		return channel;
	}

	bool remote_write_file(HANDLE hprocess, vm_channel* channel, const char* filepath) {
		LARGE_INTEGER li = {};
		INT32 signal = 1, ready = 1;

		printf("[INF] Reading target ELF file.\n");
		HANDLE hfile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);                 
		if (hfile == INVALID_HANDLE_VALUE) {
			return false;
		}

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

		printf("[INF] Writing ELF file to channel.\n");
		while (sent < total) {
			DWORD to_read = (DWORD)MIN(sizeof(buffer), total - sent);	
			DWORD read = 0;
			SIZE_T write = 0;

			if (!ReadFile(hfile, buffer, to_read, &read, nullptr)) {
				printf("[ERR] Unable to read from file.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}
			if (read == 0) {
				printf("[ERR] Unexpected EOF.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}
			LPVOID remote = (LPVOID)(channel->view.buffer + sent);
			if (!WriteProcessMemory(hprocess, remote, buffer, read, &write) || write != read) {
				printf("[ERR] Unable to write file to remote process.\n GetLastError=0x%08x\n", GetLastError());
				CloseHandle(hfile);
				return false;
			}

			sent += read;
		}

 		SIZE_T write = 0;
		if (!WriteProcessMemory(hprocess, (LPVOID)channel->view.write_size, (LPCVOID)&total, sizeof(SIZE_T), &write) || write != sizeof(SIZE_T)) {
			printf("[ERR] channel write error (write_size).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		if (!WriteProcessMemory(hprocess, (LPVOID)channel->ipc.signal, (LPCVOID)&signal, sizeof(INT32), &write) || write != sizeof(INT32)) {
			printf("[ERR] channel write error (ipc.signal).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		if (!WriteProcessMemory(hprocess, (LPVOID)channel->ready, (LPCVOID)&ready, sizeof(INT32), &write) || write != sizeof(INT32)) {
			printf("[ERR] channel write error (ready).\n GetLastError=0x%08x\n", GetLastError());
			return false;
		}

		printf("[+] ELF loaded into shared memory\n");
		return true; 
	}
}
#endif // HYPRLOAD_HPP
