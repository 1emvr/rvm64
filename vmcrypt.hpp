#ifndef VMCRYPT_HPP
#define VMCRYPT_HPP
#include "vmmain.hpp"

namespace rvm64::crypt {
	constexpr uintptr_t encrypt_ptr(uintptr_t ptr) {
		return ptr ^ DKEY;
	}

	_vmcall uintptr_t decrypt_ptr(uintptr_t ptr) {
		return ptr ^ DKEY;
	}
};
#endif // VMCRYPT_HPP
