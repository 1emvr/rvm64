#include <errhandlingapi.h>
#include <setjmp.h>

#include "vmmain.hpp"
#include "vmcode.hpp"
#include "vmcommon.hpp"
#include "vmveh.hpp"
#include "rvni.hpp"
#include "mock.hpp"


namespace rvm64::entry {
	_vmcall void vm_exit() {
		RemoveVectoredExceptionHandler(veh_handle);
		rvm64::memory::memory_end();
	}

	_vmcall void vm_init(uint8_t *packet_data, size_t packet_size) {
		veh_handle = AddVectoredExceptionHandler(1, vm_exception_handler);

		rvm64::memory::memory_init(packet_size + VM_PROCESS_PADDING); // init vmcs->process.address 
		rvm64::elf::load_elf_image(packet_data, packet_size);

		rvm64::elf::patch_elf_plt(vmcs->process.address);
		vmcs->vregs[sp] = (uintptr_t)(vmcs->vstack + VSTACK_MAX_CAPACITY);

		vmcs->cache
			? rvm64::mock::cache_file(data)
			: rvm64::mock::destroy_file(data);
	}

	_vmcall void vm_entry() {
		if (setjmp(vmcs->trap_handler)) { }

		while (!vmcs->halt) {
			int32_t opcode = *(int32_t*)vmcs->pc;

			if (opcode == RV64_RET) {
				if (!PROCESS_MEMORY_IN_BOUNDS(vmcs->vregs[regenum::ra])) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}
			rvm64::decoder::vm_decode(opcode);
			vmcs->pc += 4;
		}
};

namespace rvm64 {
	_native int32_t vm_main(shared_buffer *packet) {
		save_host_context();

		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}

		rvm64::entry::vm_init(packet->address, packet->size); 
		rvm64::entry::vm_entry();

defer:
		rvm64::entry::vm_exit();
		restore_host_context();
		return vmcs->csr.m_cause;
	}
};

int main() {
	shared_buffer *packet = nullptr;

	vmcs_t vm_instance = { };
	vmcs = &vm_instance;

	// NOTE: vm_exception_handler is not set-up so halt cannot be called on.
	while (!vmcs->halt) {
		if ((packet = rvm64::mock::read_shared_memory())) {
			break;
		}
		Sleep(10);
	}
    return rvm64::vm_main(packet);
}

