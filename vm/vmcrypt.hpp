#ifndef VMCRYPT_HPP
#define VMCRYPT_HPP
#include "../include/vmmain.hpp"

// TODO: use elf64_ehdr->e_entry as initial decryption key.
constexpr UINT_PTR EncryptPtr (
		_In_ const UINT_PTR ptr, 
		_In_ const UINT_PTR key) 
{
	return ptr ^ key;
}

inline UINT_PTR DecryptPtr (
		_In_ const UINT_PTR ptr, 
		_In_ const UINT_PTR key) 
{
	return ptr ^ key;
}
#endif // VMCRYPT_HPP
