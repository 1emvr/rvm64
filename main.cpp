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

	_vmcall void vm_init() {
		veh_handle = AddVectoredExceptionHandler(1, vm_exception_handler);
		vm_buffer_t *data = rvm64::mock::read_file();

		data->size += VM_PROCESS_PADDING;
		rvm64::memory::memory_init(data->size);

		rvm64::elf::load_elf_image(data->address, data->size);
		rvm64::elf::patch_elf_plt(vmcs->process.address);

		vmcs->vregs[sp] = (uintptr_t)(vmcs->vstack + VSTACK_MAX_CAPACITY);

		vmcs->cache
			? rvm64::mock::cache_file(data)
			: rvm64::mock::destroy_file(data);
	}

	_vmcall void vm_entry() {
		save_host_context();
		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}

		vm_init(); 
		if (setjmp(vmcs->trap_handler)) { }

		while (!vmcs->halt) {
			int32_t opcode = *(int32_t*)vmcs->pc;

			if (opcode == RV64_RET) {
				if (PROCESS_MEMORY_OOB(vmcs->vregs[regenum::ra])) {
					CSR_SET_TRAP(nullptr, environment_exit, 0, 0, 1);
				}
			}
			rvm64::decoder::vm_decode(opcode);
			vmcs->pc += 4;
		}
defer:
		vm_exit();
		restore_host_context();
		return;
	}
};

namespace rvm64 {
	_native int vm_main() {
		vmcs_t vm_instance = { };
		vmcs = &vm_instance;

		rvm64::rvni::resolve_ucrt_imports();
		rvm64::entry::vm_entry();

		return vmcs->csr.m_cause;
	}
};

int main() {
    rvm64::vm_main();
}

