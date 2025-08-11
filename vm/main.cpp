#include <windows.h>

#include "vmmain.hpp"
#include "vmentry.hpp"
#include "vmcommon.hpp"

namespace rvm64 {
	_native int32_t vm_main() {
		save_host_context();

		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}

		rvm64::entry::vm_init(vmcs->channel->v_mapping, vmcs->channel->mapping.size); 
		rvm64::entry::vm_entry(); // patch here before starting the vm -> hook for supervisor
defer:
		rvm64::entry::vm_exit();

		restore_host_context();
		return vmcs->csr.m_cause;
	}
};

int main() {
	vmcs_t vm_instance = { };
	vmcs = &vm_instance;

	while (true) {
		if (rvm64::ipc::read_channel_buffer()) {
			break;
		}
		Sleep(10);
	}

    return rvm64::vm_main();
}

