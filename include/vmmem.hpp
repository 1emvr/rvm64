#ifndef VMMEM_H
#define VMMEM_H
#include <stdio.h>
#include "vmmain.hpp"

namespace rvm64::memory {
    _vmcall void vm_set_load_rsv(int hart_id, uintptr_t address) {
        WaitForSingleObject(vmcs_mutex, INFINITE);

        vmcs->load_rsv_addr = address; // vmcs_array[hart_id]->load_rsv_addr = address;
        vmcs->load_rsv_valid = true; // vmcs_array[hart_id]->load_rsv_valid = true;

        ReleaseMutex(vmcs_mutex);
    }

    _vmcall void vm_clear_load_rsv(int hart_id) {
        WaitForSingleObject(vmcs_mutex, INFINITE);

        vmcs->load_rsv_addr = 0LL; // vmcs_array[hart_id]->load_rsv_addr = 0LL;
        vmcs->load_rsv_valid = false; // vmcs_array[hart_id]->load_rsv_valid = false;

        ReleaseMutex(vmcs_mutex);
    }

    _vmcall bool vm_check_load_rsv(int hart_id, uintptr_t address) {
        int valid = 0;

        WaitForSingleObject(vmcs_mutex, INFINITE);
        valid = (vmcs->load_rsv_valid && vmcs->load_rsv_addr == address); // (vmcs_array[hart_id]->load_rsv_valid && vmcs_array[hart_id]->load_rsv_addr == address)

        ReleaseMutex(vmcs_mutex);
        return valid;
    }

	bool write_process_memory(HANDLE hprocess, uintptr_t address, const uint8_t *buffer, size_t length, size_t *write) {
		DWORD oldprot = 0;
		if (!VirtualProtectEx(hprocess, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldprot)) {
			return false;
		}

		BOOL result = WriteProcessMemory(hprocess, (LPVOID)address, buffer, length, write);

		VirtualProtectEx(hprocess, (LPVOID)address, length, oldprot, &oldprot);
		FlushInstructionCache(hprocess, (LPCVOID)address, length);

		return result && *write == length;
	}

	bool read_process_memory(HANDLE hprocess, uintptr_t address, uint8_t *read_bytes, size_t length) {
		SIZE_T read = 0;
		BOOL result = ReadProcessMemory(hprocess, (LPCVOID)address, (LPVOID)read_bytes, length, &read);

		return result && read == length;
	}

	// TODO:
	_native void cache_data(uintptr_t data, size_t size) {
		return;
	}

	_native void destroy_data(uintptr_t data, size_t size) {
		return;
	}
};

#endif // VMMEM_H
