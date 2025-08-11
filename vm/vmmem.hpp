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

		// TODO: Setup memory view with self.address and other relevant data.
		// NOTE: The vm elf can be a mapped view. This will be simpler and probably cleaner. We don't need a real address.
		
		vmcs->channel = (vm_channel*)rvm64::memory::allocate_local_2GB_range(GetCurrentProcess(), PAGE_EXECUTE_READWRITE, GetModuleHandle(0), sizeof(vm_channel));
		if (!vmcs->channel) {
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
		}

		vmcs->channel.self = vmcs->channel;
		vmcs->channel.header_size = (sizeof(uint64_t) * 4) + (sizeof(HANDLE) + sizeof(LPVOID));

		vmcs->channel.magic1 = VM_MAGIC1;
		vmcs->channel.magic2 = VM_MAGIC2;

		vmcs->channel->mapping.h_mapping = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 0x100000, VM_MAPPED_FILE_NAME);
		vmcs->channel->mapping.size = 0x100000;

		if (!vmcs->channel->mapping.h_mapping) {
			vmcs->channel->mapping.error = GetLastError();
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
		}

		vmcs->channel->mapping.v_mapping = MapViewOfFile(vmcs->channel->mapping.h_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0x100000);
		if (!vmcs->channel->mapping.v_mapping) {
			vmcs->channel->mapping.error = GetLastError();
		    CSR_SET_TRAP(nullptr, load_access_fault, GetLastError(), 0, 1);
		}
	}

	_native void memory_end() {
		if (vmcs->process.address) {
			VirtualFree(vmcs->process.address, 0, MEM_RELEASE);
		}
		if (!vmcs->mem_view->buffer.address) {
			HeapFree(GetProcessHeap(), 0, (LPVOID)vmcs->mem_view->buffer.address);
		}
	}
};

#endif // VMMEM_H
