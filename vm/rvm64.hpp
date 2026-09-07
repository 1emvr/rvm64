#ifndef RVM64
#define RVM64

#include rvm64_common.hpp
#include rvm64_thread.hpp
#include rvm64_image.hpp


#ifdef __cplusplus
extern "C" {
#endif
	VOID save_registers (_In_ const CPU_CONTEXT* context);
	VOID load_registers (_In_ const CPU_CONTEXT* context);

	VMCS* DATA_SCN g_vmcs = nullptr;
#ifdef __cplusplus
}
#endif


namespace thread 
{
	VOID NATIVE_CALL thread_main (_In_ const LPVOID parameters) {
		ThreadArgs *args = (ThreadArgs *)parameters;
		// this is where the machine code FDX cycle will take place
		return;
	}

	BOOL NATIVE_CALL start_thread (
			_Out_ 		HANDLE* 				handle,
			_In_ const 	LPTHREAD_START_ROUTINE	call,
			_In_ const 	LPVOID 					args) 
	{
		*handle = CreateThread (nullptr, 0, call, args, 0, nullptr); 

		if (*handle == nullptr) {
			return false;
		}
		return true;
	}
} // namespace thread
  
  
namespace rvm 
{
	using namespace image_calculate;
	using namespace image_load;

	VOID NATIVE_CALL rvm64_main () // TODO: keep running forever, waiting for new packets, re-evaluating memory and task ??
	{ 
		UINT_PTR data 		= g_vmcs->code_arena->data;
		ElfEntry *entries 	= g_vmcs->code_arena->entries;

		if (!calculate_runtime_size ()) { // count the number of threads + iterate through headers and find expanded size of all ELF files
			goto defer;
		}
		if (g_vmcs->code_arena->count == 0 || g_vmcs->code_arena->count > MAX_VM_THREADS) {
			goto defer;
		}
		/* 
		   if (!calculate_runtime_memory ()) { // should either move infinite threads to their own memory or memory manager should keep tabs on everything
		   goto defer;
		   }
		   */ 

		for (UINT8 thread_index = 0; thread_index < a->count; thread_index++) {
			UINT_PTR elf_base 	= data + entires [thread_index].elf_off; 
			UINT_PTR param_base = data + entries [thread_index].param_off;

			if (param_base [0] == 0) param_base = nullptr;

			g_vmcs->t_args [thread_index].elf_base 		= elf_base;
			g_vmcs->t_args [thread_index].param_base 	= param_base;

			UINT64 type 		= g_vmcs->t_type [thread_index];
			THREAD_ARGS *args 	= &g_vmcs->t_args [thread_index];

			// need a memory manager that can just check if a region is still locked instead of keeping separate threads. 
			if (type == one_thread) {
				if (!start_thread (&g_vmcs->one_thread [thread_index], (LPTHREAD_START_ROUTINE)thread_main, (LPVOID)args)) {
					a->count -= 1;
				}
			} else if (type == inf_thread) {
				if (!start_thread (&g_vmcs->inf_thread [thread_index], (LPTHREAD_START_ROUTINE)thread_main, (LPVOID)args)) { 
					a->count -= 1;
				}
			} else {
				return;
				// error
			}
		}

		DWORD result = WaitForMultipleObjects ((DWORD)a->count, g_vmcs->one_thread, true, INFINITE); 

		for (HANDLE handle_index = 0; handle_index < a->count; handle_index++) {
			if (g_vmcs->one_thread [handle_index]) {

				CloseHandle (threads [handle_index]);
				HeapFree (threads [handle_index]);
			}
		}
		// post_thread_response () ??
defer:
		return;
	}


	VOID NATIVE_CALL rvm64_start (
			_In_ const UINT_PTR* data, 
			_In_ const UINT_PTR* data_size) 
	{
		VMCS instance = { };
		g_vmcs = &instance; 

		rvm64_memory_init (data, data_size); // the problem is we need to continue running and listening for new packets...
		rvm64_main (); 
	}
} // namespace rvm
#endif //RVM64
