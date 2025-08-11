#ifndef VMMEM_H
#define VMMEM_H
#include <stdio.h>
#include "vmmain.hpp"

namespace rvm64::memory {
	_native void memory_init(size_t process_size) {
		vmcs->process.size = process_size;
	    vmcs->process.address = (uint8_t*)vmcs->channel->view.buffer;

		if (!vmcs->process.address) {
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
	    }
	}

	_native void memory_end() {
		if (vmcs->process.address) {
			VirtualFree((LPVOID)vmcs->process.address, 0, MEM_RELEASE);
		}
	}

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

	bool write_process_memory(HANDLE hprocess, uintptr_t address, const uint8_t *new_bytes, size_t length) {
		DWORD oldprot = 0;
		SIZE_T written = 0;

		if (!VirtualProtectEx(hprocess, (LPVOID)address, length, PAGE_EXECUTE_READWRITE, &oldprot)) {
			return false;
		}

		BOOL result = WriteProcessMemory(hprocess, (LPVOID)address, new_bytes, length, &written);

		VirtualProtectEx(hprocess, (LPVOID)address, length, oldprot, &oldprot);
		FlushInstructionCache(hprocess, (LPCVOID)address, length);

		return result && written == length;
	}

	bool read_process_memory(HANDLE hprocess, uintptr_t address, uint8_t *read_bytes, size_t length) {
		SIZE_T read = 0;
		BOOL result = ReadProcessMemory(hprocess, (LPCVOID)address, (LPVOID)read_bytes, length, &read);

		return result && read == length;
	}

	_native void* allocate_2GB_range(HANDLE handle, uintptr_t base, DWORD protect, SIZE_T size) {
		SYSTEM_INFO si; 
		GetSystemInfo(&si);

		uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
		uintptr_t add = gran - 1, mask = ~add; 
		uintptr_t lo = (base >= 0x80000000ULL) ? ((base - 0x80000000ULL + add) & mask) : 0;
		uintptr_t hi = (base <= (uintptr_t)(~0ULL - 0x80000000ULL)) ? ((base + 0x80000000ULL) & mask) : (uintptr_t)(~0ULL);

		MEMORY_BASIC_INFORMATION mbi;
		uintptr_t pos = lo;

		while (pos < hi) {
			if (!VirtualQueryEx(handle, (LPCVOID)pos, &mbi, sizeof(mbi))) {
				printf("[ERR] allocate_2GB_range: VirtualQueryEx failed: 0x%lx\n", GetLastError());
				break; // Low OOB
			}
			uintptr_t region_base = (uintptr_t)mbi.BaseAddress;
			uintptr_t region_end = region_base + mbi.RegionSize;

			if (mbi.State == MEM_FREE) {
				uintptr_t check_addr = (region_base + add) & mask;

				if (check_addr < region_end && check_addr + size <= region_end && check_addr >= lo && check_addr + size <= hi) {
					void *ptr = VirtualAllocEx(handle, (LPVOID)check_addr, size, MEM_COMMIT | MEM_RESERVE, protect);
					if (!ptr) {
						printf("[ERR] allocate_2GB_range: VirtualAllocEx failed: 0x%lx\n", GetLastError());
						return nullptr;
					}

					return ptr;
				}
			}
			pos = region_end;
		}

		pos = hi;
		while (pos > lo) {
			uintptr_t probe = pos - gran;
			if (!VirtualQueryEx(handle, (LPCVOID)(pos - gran), &mbi, sizeof(mbi))) {
				printf("[ERR] allocate_2GB_range: VirtualQueryEx failed: 0x%lx\n", GetLastError());
				break; // High OOB, we're cooked...
			}
			uintptr_t region_base = (uintptr_t)mbi.BaseAddress;
			uintptr_t region_end = region_base + mbi.RegionSize;

			if (mbi.State == MEM_FREE) {
				if (region_end > size) {
					uintptr_t check_addr = ((region_end - size) & mask);

					if (check_addr >= region_base && check_addr + size <= region_end && check_addr >= lo && check_addr <= hi) {
						void *ptr = VirtualAllocEx(handle, (LPVOID)check_addr, size, MEM_COMMIT | MEM_RESERVE, protect);
						if (!ptr) {
							printf("[ERR] allocate_2GB_range: VirtualAllocEx failed: 0x%lx\n", GetLastError());
							return nullptr;
						}

						return ptr;
					}
				}
			}
			pos = region_base;
		}
		return nullptr;
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
