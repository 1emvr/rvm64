#ifndef HYPRDBG_HPP
#define HYPRDBG_HPP
#include <windows.h>
#include <inttypes.h>
#include <string>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <vector>

#include "../include/vmipc.hpp"
#include "../include/vmmain.hpp"
#include "../include/vmcommon.hpp"
#include "../include/capstone/capstone.h"

#define CMD_NEXT 0x1ULL

namespace superv::debug {
	void clear_screen() {
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		DWORD count = 0, cell_count = 0;
		COORD home_coords = { 0, 0 };

		HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (h_stdout == INVALID_HANDLE_VALUE) {
			return;
		}
		if (!GetConsoleScreenBufferInfo(h_stdout, &csbi)) {
			return;
		}

		cell_count = csbi.dwSize.X * csbi.dwSize.Y;
		if (!FillConsoleOutputCharacterA(h_stdout, ' ', cell_count, home_coords, &count) ||
			!FillConsoleOutputAttribute(h_stdout, csbi.wAttributes, cell_count, home_coords, &count)) {
			return;
		}

		SetConsoleCursorPosition(h_stdout, home_coords);
	}

	void send_signal(win_process* proc, vm_channel* channel, uint64_t signal) {
		switch(signal) {
			case CMD_NEXT: 
				{
					rvm64::ipc::set_channel_ready(proc->handle, channel, 1);
					break;
				}
			default:
				break;
		}
	}

	void print_decode(win_process* proc, vm_channel* channel) {
		vmcs_t vmcs{};

		if (!rvm64::memory::read_process_memory(proc->handle, (uintptr_t)channel->self, (uint8_t*)&vmcs, sizeof(vmcs))) {
			std::printf("[ERR] unable to read vmcs from remote (GLE=0x%lx)\n", (unsigned long)GetLastError());
			return;
		}

		// clear screen (if you have a helper, otherwise remove)
		clear_screen();

		std::printf("[DBG] vmcs.pc = 0x%016" PRIxPTR "\n", (uintptr_t)vmcs.pc);
		std::printf("[DBG] vmcs->vregs:\n");

		for (int i = 0; i < 32; ++i) {
			std::printf("x%02d = 0x%016" PRIxPTR "%s", i, (uintptr_t)vmcs.vregs[i], ((i + 1) % 8 == 0) ? "\n" : "  ");
		}
		std::printf("\n");

		constexpr int INS_BEFORE = 4;
		constexpr int INS_AFTER  = 4;
		constexpr size_t BYTES   = (INS_BEFORE + INS_AFTER + 1) * 4;

		uintptr_t start = vmcs.pc - INS_BEFORE * 4;
		uint8_t buffer[64] = {};
		SIZE_T bytes_read = 0;

		// Check memory region before reading
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQueryEx(proc->handle, (LPCVOID)start, &mbi, sizeof(mbi))) {
			std::printf("[ERR] VirtualQueryEx failed (GLE=%lu)\n", GetLastError());
			return;
		}
		if (!(mbi.State & MEM_COMMIT)) {
			std::printf("[ERR] Region at %p not committed (State=0x%lx)\n",
					mbi.BaseAddress, mbi.State);
			return;
		}

		// Actually read memory
		if (!ReadProcessMemory(proc->handle, (LPCVOID)start, buffer, sizeof(buffer), &bytes_read)) {
			std::printf("[ERR] could not read instructions near PC (GLE=%lu)\n", GetLastError());
			return;
		}
		std::printf("[DBG] ReadProcessMemory got %zu bytes from %p\n", bytes_read, (void*)start);

		// Capstone disassembly
		csh handle;
		if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
			std::printf("[ERR] capstone init failed\n");
			return;
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

		cs_insn* insn = nullptr;
		size_t count = cs_disasm(handle, buffer, bytes_read, start, 0, &insn);

		if (count == 0) {
			std::printf("[ERR] capstone disasm failed\n");
		} else {
			for (size_t i = 0; i < count; i++) {
				bool at_pc = (insn[i].address == vmcs.pc);
				std::printf("%s 0x%llx:\t%s\t%s\n", at_pc ? " >" : "  ", (unsigned long long)insn[i].address, insn[i].mnemonic, insn[i].op_str);
			}
			cs_free(insn, count);
		}

		cs_close(&handle);
	}

	int64_t user_loop(win_process* proc, vm_channel* channel) {
		std::string last_cmd;
		std::cout << "[INF] press enter to continue.\n" << std::flush;

		if (!std::getline(std::cin, last_cmd)) {
			return -1;
		}
		if (last_cmd == "q" || last_cmd == "quit" || last_cmd == "exit") {
			return -1;
		}

		last_cmd.clear();

		while (true) {
			print_decode(proc, channel);

			std::cout << "> " << std::flush;
			std::string cmd;

			if (!std::getline(std::cin, cmd)) break;
			if (cmd.empty()) cmd = last_cmd; else last_cmd = cmd;

			if (cmd == "q" || cmd == "quit" || cmd == "exit") {
				break;
			}

			if (cmd == "clr" || cmd == "clear") {
				clear_screen();
				continue;
			}

			if (cmd == "n" || cmd == "next") {
				send_signal(proc, channel, CMD_NEXT);
				continue;
			}

			// TODO: other commands...

			Sleep(50);
		}

		clear_screen();
		return 0;
	}
}
#endif // HYPRDBG_HPP
