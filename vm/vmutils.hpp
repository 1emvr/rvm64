#ifndef VMUTILS_H
#define VMUTILS_H

#include <windows.h>
#include "../include/vmmain.hpp"

inline int32_t sign_extend(uint32_t val, int bits) {
	int shift = 32 - bits;
	return (int32_t)(val << shift) >> shift;
}

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_ARM64)
inline uint8_t shamt_i(uint32_t opcode) {
    return (opcode >> 20) & 0x3F;  
}
#elif defined(_M_IX86) || defined(__i386__) || defined(_M_ARM)
inline uint8_t shamt_i(uint32_t opcode) {
    return (opcode >> 20) & 0x1F;  
}
#else
#error Unsupported architecture: Define shamt_i() masking manually.
#endif

inline int32_t imm_u(uint32_t opcode) {
	return (int32_t) opcode & 0xFFFFF000;
}

inline int32_t imm_i(uint32_t opcode) {
	int32_t imm = opcode >> 20;
	return sign_extend(imm, 12);
}


inline int32_t imm_s(uint32_t opcode) {
	uint32_t imm11_5 = (opcode >> 25) & 0x7f;
	uint32_t imm4_0 = (opcode >> 7) & 0x1f;
	uint32_t imm = (imm11_5 << 5) | imm4_0;

	return sign_extend(imm, 12);
}

inline int32_t imm_b(uint32_t opcode) {
	int32_t imm = (((opcode >> 31) & 1) << 12)
	              | (((opcode >> 25) & 0x3F) << 5)
	              | (((opcode >> 8) & 0xF) << 1)
	              | (((opcode >> 7) & 1) << 11);
	return sign_extend(imm, 13);
}

inline int32_t imm_j(uint32_t opcode) {
	int32_t imm = (((opcode >> 31) & 1) << 20)
	              | (((opcode >> 21) & 0x3FF) << 1)
	              | (((opcode >> 20) & 1) << 11)
	              | (((opcode >> 12) & 0xFF) << 12);
	return sign_extend(imm, 21);
}

namespace simple_map {
	template<typename K, typename V>
		struct entry {
			K key;
			V value;
		};

	template<typename K, typename V>
		class unordered_map {
			public:
				entry<K, V> *entries = { };
				size_t capacity{ };

				unordered_map() = default;
				~unordered_map() {
					if (entries) {
						HeapFree(GetProcessHeap(), 0, entries);
					}
				}

				void push(K key, V value) {
					auto temp = (entry<K, V> *) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, this->entries, sizeof(entry<K, V>) * (this->capacity + 1));
					if (!temp) {
						return;
					}

					this->entries = temp;
					this->entries[this->capacity].key = key;
					this->entries[this->capacity].value = value;
					this->capacity += 1; // ...past the end
				}

				entry<K, V>* find(K key) {
					if (!this->entries || !this->capacity) {
						return end();
					}
					for (size_t i = 0; i < this->capacity; i++) {
						if (this->entries[i].key == key) {
							return this->entries[i];
						}
					}
					return end();
				}

				void pop(K key) {
					if (!this->entries) {
						return;
					}
					for (size_t i = 0; i < this->capacity; i++) {
						if (this->entries[i].key == key) {
							for (size_t j = i; j < this->capacity - 1; j++) {
								this->entries[j] = this->entries[j + 1];
							}
							this->capacity -= 1;

							if (this->capacity > 0) {
								this->entries = (entry<K, V> *) HeapReAlloc(
										GetProcessHeap(), HEAP_ZERO_MEMORY, this->entries, sizeof(entry<K, V>) * this->capacity);
							} else {
								HeapFree(GetProcessHeap(), 0, this->entries);
								this->entries = nullptr;
							}
							return;
						}
					}
				}

				entry<K, V> *begin() {
					return this->entries;
				}

				entry<K, V> *end() {
					return this->entries + this->capacity;
				}

		};
};
#endif //VMUTILS_H
