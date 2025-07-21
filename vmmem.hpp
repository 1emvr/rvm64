#ifndef VMMEM_H
#define VMMEM_H
#include "vmmain.hpp"
#include "vmelf.hpp"

struct exec_region_t {
	uintptr_t base;
	size_t size;
};

_data exec_region_t native_exec_regions[128] = { };
_data size_t native_exec_count = 0;


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

	_native void memory_init(size_t process_size) {
    	NTSTATUS status = 0;

		vmcs->process.size = process_size;
	    vmcs->process.address = (uint8_t*)VirtualAlloc(nullptr, vmcs->process.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (vmcs->process.address == nullptr) {
		    CSR_SET_TRAP(nullptr, load_access_fault, status, 0, 1);
	    }
	}

	_native void memory_end() {
    	NTSTATUS status = 0;
		if (vmcs->process.address == nullptr) {
			return;
		}

		VirtualFree(vmcs->process.address, vmcs->process.size, MEM_RELEASE);
	}

	_native bool memory_register(uintptr_t base, size_t size) {
		if (native_exec_count >= 128) {
			return false;
		}

		native_exec_regions[native_exec_count++] = { base, size };
		return true;
	}

	_native bool memory_unregister(uintptr_t base) {
		bool success = false;
		for (size_t i = 0; i < native_exec_count; ++i) {
			if (native_exec_regions[i].base == base) {

				for (size_t j = 0; j < native_exec_count - 1; ++j) {
					native_exec_regions[j] = native_exec_regions[j + 1];
				}
				native_exec_regions[native_exec_count - 1] = { 0, 0 };
				--native_exec_count;

				success = true;
				break;
			}
		}
		return success;
	}

	_native bool modify_protection() {
		bool success = true;
		// TODO: when calling mprot() passthru this function first.
		// NOTE: is this necessary? we could just use mprotect -> VirtualProtect and whatever happens, happens...
		return success;
	}

	_native bool memory_check() {
		for (auto& rgn : native_exec_rgnions) {
			auto start = rgn.base;
			auto end = start + rgn.size;

			if (vmcs->pc >= start && vmcs->pc < end) {
				return true;
			}
		}
		return false;
	}
};

#endif // VMMEM_H
