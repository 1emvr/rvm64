#ifndef VMRWX_HPP
#define VMRWX_HPP

#ifdef DEBUG
#define DEBUGBREAK __debugbreak()
#else
#define DEBUGBREAK
#endif


#define PROCESS_MEMORY_OOB(addr)  										\
	((addr) < (uintptr_t)vmcs->process.address || 						\
	 (addr) >= (uintptr_t)(vmcs->process.address + vmcs->process.size))


#define STACK_MEMORY_OOB(addr) 											\
	((addr) < (uintptr_t)vmcs->vstack || 								\
	 (addr) >= (uintptr_t)(vmcs->vstack + VSTACK_MAX_CAPACITY))


#define mem_read_check(T, addr)  											\
do {                                       									\
    if ((addr) % sizeof(T) != 0) {                                         	\
        CSR_SET_TRAP(vmcs->pc, load_address_misaligned, 0, addr, 1);       	\
    }                                                                      	\
	if (STACK_MEMORY_OOB(addr)) { 											\
		if (PROCESS_MEMORY_OOB(addr)) {              						\
			CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, addr, 1);      	\
		} 																	\
	}                                                                      	\
} while (0)


#define mem_write_check(T, addr) 											\
do {                                      									\
    if ((addr) % sizeof(T) != 0) {                                         	\
        CSR_SET_TRAP(vmcs->pc, store_amo_address_misaligned, 0, addr, 1);  	\
    }                                                                      	\
	if (STACK_MEMORY_OOB(addr)) {											\
		if (PROCESS_MEMORY_OOB(addr)) {              						\							 
			CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, addr, 1);     \
		} 																	\
	}                                                                      	\
} while (0)


#define unwrap_opcall(hdl_idx) 									\
	do { 														\
		uintptr_t a = ((uintptr_t*)dispatch_table)[hdl_idx];	\
		uintptr_t b = rvm64::crypt::decrypt_ptr((uintptr_t)a);	\
		void (*fn)() = (void (*)())(b);							\
		fn();													\
	} while(0)


#define mem_read(T, retval, addr)  								\
	do {														\
		mem_read_check(T, ((uintptr_t)addr));					\
		retval = *(T *)((uintptr_t)addr); 						\
	} while(0)


#define mem_write(T, addr, value)  								\
	do {														\
		mem_write_check(T, ((uintptr_t)addr));					\
		*(T *)((uintptr_t)addr) = value;  						\
	} while(0)


#define reg_read(T, dst, reg_idx) 								\
	do { 														\
		dst = (T)vmcs->vregs[(reg_idx)];						\
	} while(0)


#define reg_write(T, reg_idx, src) 								\
	do { 														\
		if (reg_idx != 0) { 									\
			vmcs->vregs[(reg_idx)] = (T)(src);					\
		} 														\
	} while(0)


#define scr_read(T, dst, scr_idx) 								\
	do { 														\
		dst = (T)vmcs->vscratch[(scr_idx)];						\
	} while(0)


#define scr_write(T, scr_idx, src) 								\
	do { 														\
		vmcs->vscratch[(scr_idx)] = (T)(src);					\
	} while(0)
#endif // VMRWX_HPP
