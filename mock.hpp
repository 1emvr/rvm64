#ifndef MOCK_H
#define MOCK_H
#include <windows.h>
#include <string.h>

#include "vmmain.hpp"
#include "vmcommon.hpp"

namespace rvm64::mock {
	_native void cache_file(vm_buffer_t *data) {
		// only for mock-up
	};

	_native void destroy_file(vm_buffer_t *data) {
		if (!data) {
			return;
		}
		if (data->address) {
			HeapFree(GetProcessHeap(), 0, data->address);
			data->address = nullptr;
			data->size = 0;
		}

		HeapFree(GetProcessHeap(), 0, data);
	}

	_native vm_buffer_t* read_file() {
		DWORD bytes_read = 0;
		BOOL success = false;

		auto data = (vm_buffer_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_buffer_t));
		if (!data) {
			return nullptr;
		}
		HANDLE handle = CreateFileA("C:/Users/lemur/github/rvm64/test.elf", GENERIC_READ, FILE_SHARE_READ, nullptr,
									OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (handle == INVALID_HANDLE_VALUE) {
			data->stat = GetLastError();
			goto defer;
		}

		data->size = GetFileSize(handle, nullptr);
		if (data->size == INVALID_FILE_SIZE || data->size == 0) {
			data->stat = GetLastError();
			goto defer;
		}

		data->address = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data->size);

		if (!ReadFile(handle, data->address, data->size, &bytes_read, nullptr) ||
		    bytes_read != data->size) {
			data->stat = GetLastError();
			goto defer;
		}
		success = true;

	defer:
		if (handle) {
			CloseHandle(handle);
		}
		if (!success && data != nullptr) {
			HeapFree(GetProcessHeap(), 0, data);
			data = nullptr;
		}

		return data;
	}
};
#endif // MOCK_H
