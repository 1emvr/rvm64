#ifndef VMMEM_H
#define VMMEM_H
#include "vmmain.hpp"
#include "vmelf.hpp"

struct exec_region_t {
	uintptr_t base;
	size_t size;
};

_data exec_region_t native_exec_regions[128];
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

	_native bool register_memory() {
		// TODO: when calling mmap() passthru this function first.
		bool success = true;
		return success;
	}

	_native bool unregister_memory() {
		// TODO: when calling munmap() passthru this function first.
		bool success = true;
		return success;
	}

	_native bool modify_protection() {
		// TODO: when calling mprot() passthru this function first.
		bool success = true;
		return success;
	}

	_native bool check_memory() {
		// TODO: when calling on the target address, passthru this function to check.
		bool success = true;
		return success;
	}
};

#endif // VMMEM_H
