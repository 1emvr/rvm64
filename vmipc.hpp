#ifndef HYPRIPC_HPP
#define HYPRIPC_HPP
#include "vmmain.hpp"


namespace rvm64::ipc {
	void destroy_channel() {
		if (!vmcs->channel) {
			return;
		}

		UnmapViewOfFile(vmcs->channel->view.v_mapping);
		vmcs->channel->view.v_mapping = nullptr;

		if (vmcs->channel->view.h_mapping) {
			CloseHandle(vmcs->channel->view.h_mapping);
		}

		HeapFree(GetProcessHeap(), 0, vmcs->channel);
		vmcs->channel = nullptr;
	}

	void create_channel() {
		vmcs->channel = (vm_channel*)HeapAlloc(GetProcessHeap(), 0, sizeof(vm_channel));
		vmcs->channel.self = vmcs->channel;

		vmcs->channel->view.h_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(vm_channel) + CHANNEL_BUFFER_SIZE, VM_MAPPED_FILE_NAME); 
		if (!vmcs->channel->view.h_mapping) {
			destroy_channel();
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}

		vmcs->channel->view.v_mapping = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
		if (!vmcs->channel->view.v_mapping) {
			destroy_channel();
			CSR_SET_TRAP(vmcs->pc, GetLastError(), 0, 0, 1);
		}

		vmcs->channel->view.size = CHANNEL_BUFFER_SIZE;
		vmcs->channel.header_size = (sizeof(uint64_t) * 4) + (sizeof(HANDLE) + sizeof(LPVOID));

		vmcs->channel.magic1 = VM_MAGIC1;
		vmcs->channel.magic2 = VM_MAGIC2;
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
		return true;
	}
}
#endif // HYPRIPC_HPP
