#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "../include/vmmain.hpp"

namespace superv::loader {
	BOOL write_elf_file(HANDLE hprocess, vm_channel* channel, const char* filepath) {
		LARGE_INTEGER li = {};
		INT32 signal = 1, ready = 1;

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

		while (sent < total) {
			DWORD to_read = (DWORD)min(sizeof(buffer), total - sent);	
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

 		DWORD write = 0;
		if (!WriteProcessMemory(hprocess, (LPVOID)channel->view.write_size, (LPCVOID)&total, sizeof(SIZE_T), &write) || write != sizeof(SIZE_T)) {
			printf("[ERR] channel write error (write_size).\n GetLastError=0x%08x\n", GetLastError());
			goto defer;
		}

		if (!WriteProcessMemory(hprocess, (LPVOID)channel->ipc.signal, (LPCVOID)&signal, sizeof(INT32), &write) || write != sizeof(INT32)) {
			printf("[ERR] channel write error (ipc.signal).\n GetLastError=0x%08x\n", GetLastError());
			goto defer;
		}

		if (!WriteProcessMemory(hprocess, (LPVOID)channel->ready, (LPCVOID)&ready, sizeof(INT32), &write) || write != sizeof(INT32)) {
			printf("[ERR] channel write error (ready).\n GetLastError=0x%08x\n", GetLastError());
			goto defer;
		}

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		return true; 
	}
}
#endif // HYPRLOAD_HPP
