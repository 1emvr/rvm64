#ifndef VMMEM_H
#define VMMEM_H
#include "vmmain.hpp"
#include "vmelf.hpp"

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
		vmcs->process.size = process_size;
	    vmcs->process.address = (uint8_t*)VirtualAlloc(nullptr, vmcs->process.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!vmcs->process.address) {
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
	    }

		vmcs->channel = (vm_channel*)rvm64::memory::allocate_local_2GB_range(GetCurrentProcess(), PAGE_EXECUTE_READWRITE, GetModuleHandle(0), sizeof(vm_channel));
		if (!vmcs->channel) {
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
		}
	}

	_native void memory_end() {
		if (vmcs->process.address) {
			VirtualFree(vmcs->process.address, 0, MEM_RELEASE);
		}
	}
};

#endif // VMMEM_H
