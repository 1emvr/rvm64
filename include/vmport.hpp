#pragma once

// detect MSVC vs GCC/Clang
#if defined(_MSC_VER)
  #define VM_EXTERN_C 			extern "C"
  #define VM_DATA      			
  #define VM_SECTION(secname) 	__declspec(allocate(secname))
  #define VM_UNREACHABLE() 		__assume(0)
  #define typeof(x) 			decltype(x)
#else
  #define VM_EXTERN_C 			extern "C"
  #define VM_DATA      			__attribute__((section(".data")))
  #define VM_SECTION(secname) 	__attribute__((section(secname)))
  #define VM_UNREACHABLE() 		__builtin_unreachable()
#endif
