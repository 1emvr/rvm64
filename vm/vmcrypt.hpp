#ifndef VMCRYPT_HPP
#define VMCRYPT_HPP
#include "../vmmain.hpp"

// TODO: use elf headers to find initial decryption key.
namespace rvm64::crypt {
	constexpr uintptr_t encrypt_ptr(uintptr_t ptr, uintptr_t key) {
		return ptr ^ key;
	}

	_vmcall inline uintptr_t decrypt_ptr(uintptr_t ptr, uintptr_t key) {
		return ptr ^ DKEY;
	}
};
#endif // VMCRYPT_HPP
