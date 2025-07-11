#ifndef VMRWX_HPP
#define VMRWX_HPP

#ifdef DEBUG
#undef DEBUG
#define mem_read_check(T, addr)												\
	if ((addr) % sizeof(T) != 0) {											\
		CSR_SET_TRAP(vmcs->pc, load_address_misaligned, 0, addr, 1);		\
		return;																\
	}																		\
	if ((addr) < (uintptr_t)vmcs->process.address ||						\
		(addr) >= (uintptr_t)(vmcs->process.address + vmcs->process.size)) {\
		CSR_SET_TRAP(vmcs->pc, load_access_fault, 0, addr, 1);				\
		return;																\
	}

#define mem_write_check(T, addr)											\
	if ((addr) % sizeof(T) != 0) {											\
		CSR_SET_TRAP(vmcs->pc, load_address_misaligned, 0, addr, 1); 		\
		return;																\
	}																		\
	if ((addr) < (uintptr_t)vmcs->process.address ||						\
		(addr) >= (uintptr_t)(vmcs->process.address + vmcs->process.size)) {\
		CSR_SET_TRAP(vmcs->pc, store_amo_access_fault, 0, addr, 1);			\
		return;																\
	}

#define reg_read_check(reg_idx)												\
	if ((reg_idx) > t6) {													\
		CSR_SET_TRAP(vmcs->pc, instruction_access_fault, 0, reg_idx, 1);	\
		return;																\
	}

#define reg_write_check(reg_idx)											\
	if ((reg_idx) == zr || (reg_idx) > t6) {								\
		CSR_SET_TRAP(vmcs->pc, instruction_access_fault, 0, reg_idx, 1);	\
		return;																\
	}

#define scr_read_check(scr_idx)												\
	if ((scr_idx) > imm) {													\
		CSR_SET_TRAP(vmcs->pc, instruction_access_fault, 0, scr_idx, 1);	\
		return;																\
	}

#define scr_write_check(scr_idx)											\
	if ((scr_idx) > imm) {													\
		CSR_SET_TRAP(vmcs->pc, instruction_access_fault, 0, scr_idx, 1);	\
		return;																\
	}

#define	opcall_check(hdl_idx)												\
	if ((hdl_idx) > 255) {													\
		CSR_SET_TRAP(vmcs->pc, illegal_instruction, 0, hdl_idx, 1);			\
		return;																\
	}
#else
#define mem_read_check(T, addr)		{}
#define mem_write_check(T, addr)	{}
#define reg_read_check(reg_idx)		{}
#define reg_write_check(reg_idx)	{}
#define scr_read_check(scr_idx)		{}
#define scr_write_check(scr_idx)	{}
#define	opcall_check(hdl_idx)		{}
#endif

#define unwrap_opcall(hdl_idx) 									\
	do { 														\
		opcall_check(hdl_idx);									\
		auto a = ((uintptr_t*)vmcs->dispatch_table)[hdl_idx];	\
		auto b = rvm64::crypt::decrypt_ptr((uintptr_t)a);		\
		void (*fn)() = (void (*)())(b);							\
		fn();													\
	} while(0)

#define mem_read(T, retval, addr)  								\
	do {														\
		__debugbreak();											\
		mem_read_check(T, ((uintptr_t)addr));					\
		retval = *(T *)((uintptr_t)addr); 						\
	} while(0)

#define mem_write(T, addr, value)  								\
	do {														\
		__debugbreak();											\
		mem_write_check(T, ((uintptr_t)addr));					\
		*(T *)((uintptr_t)addr) = value;  						\
	} while(0)

#define reg_read(T, dst, reg_idx) 								\
	do { 														\
		reg_read_check(reg_idx);								\
		dst = (T)vmcs->vregs[(reg_idx)];						\
	} while(0)

#define reg_write(T, reg_idx, src) 								\
	do { 														\
		reg_write_check(reg_idx);								\
		vmcs->vregs[(reg_idx)] = (T)(src);						\
	} while(0)

#define scr_read(T, dst, scr_idx) 								\
	do { 														\
		scr_read_check(scr_idx);								\
		dst = (T)vmcs->vscratch[(scr_idx)];						\
	} while(0)

#define scr_write(T, scr_idx, src) 								\
	do { 														\
		scr_write_check(scr_idx);								\
		vmcs->vscratch[(scr_idx)] = (T)(src);					\
	} while(0)
#endif // VMRWX_HPP
