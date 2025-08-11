#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP

#include "vmmain.hpp"
#include "vmscan.hpp"
#include "vmmem.hpp"

namespace rvm64::ipc {
	void destroy_channel() {
		if (!vmcs->channel) {
			return;
		}
		if (vmcs->channel->view.buffer) {
			VirtualFree(vmcs->channel->view.buffer, 0, MEM_FREE);
			vmcs->channel->view.buffer = nullptr;
			vmcs->channel->view.size = 0;
		}

		HeapFree(GetProcessHeap(), 0, vmcs->channel);
		vmcs->channel = nullptr;
	}

	void create_channel(win_process* proc) {
		vmcs->channel = (vm_channel*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		vmcs->channel.self = vmcs->channel;

		if (!vmcs->channel) {
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}

		vmcs->channel->ipc.vmcs = vmcs;
		vmcs->channel.header_size = (sizeof(uint64_t) * 4) + sizeof(LPVOID);

		vmcs->channel.magic1 = VM_MAGIC1;
		vmcs->channel.magic2 = VM_MAGIC2;

		vmcs->channel->view.size = CHANNEL_BUFFER_SIZE;
		vmcs->channel->view.buffer = rvm64::memory::allocate_2GB_range(proc->handle, PAGE_READWRITE, proc->base, VM_CHANNEL_BUFFER_SIZE); 

		if (!vmcs->channel->view.buffer) {
			destroy_channel();
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}
	}

	shared_buffer* load_vm_channel(win_process* proc) {
 		static constexpr char vm_magic[16] = "RMV64_II_BEACON_";

		auto map_offset = superv::scan::signature_scan(proc->handle, proc->base, proc->size, (const uint8_t*)vm_magic, "xxxxxxxxxxxxxxxx");
		if (!map_offset) {
			return nullptr;
		}

		vm_channel *channel = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vm_channel));
		if (!channel) {
			return nullptr;
		}

		rvm64::memory::read_proc_memory();
	}

	bool read_channel_buffer(uint8_t* data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel.v_mapping) {
			CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, 0, 1);
		}
		if (!vmcs->channel.ready) {
			return false;
		}

		memcpy(data, (uint8_t*)(vmcs->channel->view.v_mapping + offset), size);
		vmcs->channel.ready = 0;

		return true;
	}

	bool write_channel_buffer(const uint8_t* data, uintptr_t offset, size_t size) {
		if (!data || offset > CHANNEL_BUFFER_SIZE || size > CHANNEL_BUFFER_SIZE - offset) {
			return false;
		}
		if (!vmcs->channel || !vmcs->channel->view.v_mapping) {
			CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, 0, 1);
		}

		memcpy((uint8_t*)(vmcs->channel->view.v_mapping + offset), data, size);
		vmcs->channel.ready = 1;

		return true;
	}
}
#endif // HYPRIPC_HPP
