#ifndef VMRWX_HPP
#define VMRWX_HPP

#ifdef DEBUG
#define DEBUGBREAK __debugbreak()
#else
#define DEBUGBREAK
#endif


#define PROCESS_MEMORY_IN_BOUNDS(addr)  								\
	((addr) >= (uintptr_t)vmcs->proc.buffer && 							\
	 (addr) < (uintptr_t)(vmcs->proc.buffer + vmcs->proc.size))


#define STACK_MEMORY_IN_BOUNDS(addr) 									\
	((addr) >= (uintptr_t)vmcs->hdw.vstack && 							\
	 (addr) < (uintptr_t)(vmcs->hdw.vstack + VSTACK_MAX_CAPACITY))


#define mem_read_check(T, addr)  													\
	do {                                       										\
		auto m = rvm64::mmu::memory_check(addr);  									\
		if (m) { 																	\
			addr = (uintptr_t)m; 													\
			break; 																	\
		} 																			\
		if ((addr) % sizeof(T) != 0) {                                         		\
			CSR_SET_TRAP(vmcs->hdw.pc, load_address_misaligned, 0, addr, 1);       	\
		}                                                                      		\
		if (!STACK_MEMORY_IN_BOUNDS(addr) && !PROCESS_MEMORY_IN_BOUNDS(addr)) {		\
			CSR_SET_TRAP(vmcs->hdw.pc, load_access_fault, 0, addr, 1);      		\
		} 																			\
	} while (0)


#define mem_write_check(T, addr) 													\
	do {                                      										\
		auto m = rvm64::mmu::memory_check(addr);  									\
		if (m) { 																	\
			addr = (uintptr_t)m; 													\
			break; 																	\
		} 																			\
		if ((addr) % sizeof(T) != 0) {                                         		\
			CSR_SET_TRAP(vmcs->hdw.pc, store_amo_address_misaligned, 0, addr, 1);  	\
		}                                                                      		\
		if (!STACK_MEMORY_IN_BOUNDS(addr) && !PROCESS_MEMORY_IN_BOUNDS(addr)) {		\
			CSR_SET_TRAP(vmcs->hdw.pc, store_amo_access_fault, 0, addr, 1);			\
		} 																			\
	} while (0)


#define reg_read(T, dst, reg_idx) 	dst = (T)vmcs->hdw.vregs[(reg_idx)]
#define scr_read(T, dst, scr_idx) 	dst = (T)vmcs->hdw.vscratch[(scr_idx)]
#define mem_read(T, retval, addr)  	mem_read_check(T, addr); retval = *(T *)(addr);

#define reg_write(T, reg_idx, src) 	if (reg_idx != 0) vmcs->hdw.vregs[(reg_idx)] = (T)(src);
#define scr_write(T, scr_idx, src) 	if (scr_idx <= imm) vmcs->hdw.vscratch[(scr_idx)] = (T)(src);
#define mem_write(T, addr, value)  	mem_write_check(T, addr); *(T *)(addr) = value;

#define unwrap_opcall(hdl_idx) 												\
	uintptr_t a = ((uintptr_t*)dispatch_table)[hdl_idx];					\
	uintptr_t b = rvm64::crypt::decrypt_ptr((uintptr_t)a, (uintptr_t)0);	\
	void (*fn)() = (void (*)())(b);											\
	fn();													

#endif // VMRWX_HPP
