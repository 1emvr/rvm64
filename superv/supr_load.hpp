#ifndef HYPRLOAD_HPP
#define HYPRLOAD_HPP
#include <windows.h>

#include "../include/vmmain.hpp"
//#include "../include/vmipc.hpp"

namespace superv::loader {
	BOOL write_elf_file(vm_channel* channel, const char* filepath) {
		BOOL success = false;
		HANDLE hfile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, 
				NULL, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);                 

		if (hfile == INVALID_HANDLE_VALUE) {
			return false;
		}

		DWORD fsize = GetFileSize(hfile, nullptr);
		if (fsize > 0x100000) {
			printf("[ERR] ELF too large for the channel buffer.\n");
			goto defer;
		}

		DWORD read = 0;
		if(!ReadFile(hfile, (LPVOID)channel->view.buffer, fsize, &read, nullptr) || read != fsize) {
			printf("[ERR] Unable to read from file.\n GetLastError=%08x\n", GetLastError());
			goto defer;
		}

		channel->view.write_size = fsize;
		channel->ipc.signal = 1; // 1 = image load
		channel->ready = 1;

		printf("[+] ELF loaded into shared memory: %zu bytes\n", fsize);
		success = true;

defer:
		if (hfile) {
			CloseHandle(hfile);
		}

		return success; 
	}
}
#endif // HYPRLOAD_HPP
