#include <errhandlingapi.h>
#include <setjmp.h>

#include "vmmain.hpp"
#include "vmcode.hpp"
#include "vmcommon.hpp"
#include "vmveh.hpp"
#include "rvni.hpp"
#include "mock.hpp"


namespace rvm64::entry {
	_vmcall void vm_init() {
		vm_buffer_t *data = nullptr;

		veh_handle = AddVectoredExceptionHandler(1, vm_exception_handler);
		vmcs->vregs[sp] = (uintptr_t)(vmcs->vstack + VSTACK_MAX_CAPACITY);

		data = rvm64::mock::read_file();
		data->size += VM_PROCESS_PADDING;

		rvm64::memory::memory_init(data->size);

		rvm64::elf::load_elf_image(data->address, data->size);
		rvm64::elf::patch_elf_plt(vmcs->process.address);

		vmcs->cache
			? rvm64::mock::cache_file(data)
			: rvm64::mock::destroy_file(data);
	}

	_vmcall void vm_loop() {
		if (!vmcs->trap_set) {
			// NOTE: setup for return-loop once a branch is taken.
			//
			vmcs->trap_handler.rip = (uintptr_t)&vm_loop;
			vmcs->trap_handler.rsp = (uintptr_t)__builtin_frame_address(0);
			vmcs->trap_set = 1;
		}

		while (!vmcs->halt) {
			int32_t opcode = *(int32_t*)vmcs->pc;

			if (opcode == JALR_RA_ZERO) {
				uintptr_t ret_addr = vmcs->vregs[ra];

				if (ret_addr < (uintptr_t)vmcs->process.address ||
				    ret_addr >= (uintptr_t)(vmcs->process.address + vmcs->process.size)) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}

			rvm64::decoder::vm_decode(opcode);
			vmcs->pc += 4;
		}
	}

	_vmcall void vm_entry() {
		save_host_context();

		vmcs->exit_handler.rip = (uintptr_t)__builtin_return_address(0);
		vmcs->exit_handler.rsp = (uintptr_t)__builtin_frame_address(0);

		vm_loop();
	}

	_vmcall void vm_exit() {
		restore_host_context();

		RemoveVectoredExceptionHandler(veh_handle);
		rvm64::memory::memory_end();
	}
};

namespace rvm64 {
	_native int64_t vm_main() {
		vmcs_t vm_instance = { };
		vmcs = &vm_instance;

		rvm64::rvni::resolve_ucrt_imports();
		rvm64::entry::vm_init();
		rvm64::entry::vm_entry();
		rvm64::entry::vm_exit();

		return (int64_t)vmcs->csr.m_cause;
	}
};

int main() {
    rvm64::vm_main();
}

