#include <windows.h>

#include "../vmipc.hpp"
#include "../vmmain.hpp"
#include "../vmcommon.hpp"

#include "vmentry.hpp"

namespace rvm64 {
	_native int32_t vm_main() {
		save_host_context();
		rvm64::ipc::vm_create_channel();

		while (true) {
			Sleep(10);
			if (vmcs->channel->ready) {
				break;
			}
		}

		if (setjmp(vmcs->exit_handler)) {
			goto defer;	
		}
		rvm64::entry::vm_init(); 
		rvm64::entry::vm_entry(); // patch here before starting the vm -> hook for supervisor
								  
defer:
		rvm64::entry::vm_exit();
		rvm64::ipc::vm_destroy_channel();

		restore_host_context();
		return vmcs->csr.m_cause;
	}
};

int main() {
	vmcs_t vm_instance = { };
	vmcs = &vm_instance;

    return rvm64::vm_main();
}

