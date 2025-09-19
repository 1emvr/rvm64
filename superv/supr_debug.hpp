#ifndef HYPRDBG_HPP
#define HYPRDBG_HPP
#include <windows.h>
#include <string>

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
		if (!FillConsoleOutputCharacter(h_stdout, ' ', cell_count, home_coords, &count) ||
			!FillConsoleOutputAttribute(h_stdout, csbi.wAttributes, cell_count, home_coords, &count)) {
			return;
		}

		SetConsoleCursorPosition(h_stdout, home_coords);
	}

	void send_signal(win_process* proc, vm_channel* channel, uint64_t signal) {

	}

	void print_decode(win_process* proc, vmcs_t* vmcs) {
		// NOTE: stealing the "pwndbg" or pwntools style of debugger. want it to look very similar.
		
		uintptr_t pc = 0;
		uintptr_t regs[32] = { };
		uintptr_t stack[7] = { };
		uint32_t ins[7] = { };

		/*
			pc is separate from the vregs, so get it 
		*/
		if (!rvm64::memory::read_process_memory(proc->handle, vmcs + offsetof(vmcs, pc), (uint8_t*)&pc, sizeof(uintptr_t))) {
			printf("[ERR] decoder unable to read process memory (vpc): GetLastError=0x%lx\n", GetLastError());
			return;
		}

		/*print all 32 registers*/
		if (!rvm64::memory::read_process_memory(proc->handle, vmcs + offsetof(vmcs, vregs), (uint8_t*)&regs, sizeof(uintptr_t) * 8)) {
			printf("[ERR] decoder unable to read process memory (vregs): GetLastError=0x%lx\n", GetLastError());
			return;
		}

		/*
		   vstack should read:
		   stack -3
		   stack -2
		   stack -1
		   current sp ->
		   stack +1
		   stack +2
		   stack +3

		   and then print all...
			 TODO: decoder for debug-info in risc-v binaries (much later date)
		*/
		if (!rvm64::memory::read_process_memory(proc->handle, vmcs + offsetof(vmcs, vstack), (uint8_t*)&stack, sizeof(uintptr_t) * 7)) {
			printf("[ERR] decoder unable to read process memory (vstack): GetLastError=0x%lx\n", GetLastError());
			return;
		}

		/*
		   program address should read:
		   ins -3
		   ins -2
		   ins -1
		   pc ->
		   ins +1
		   ins +2
		   ins +3

		   and then decode all...
		   */
		if (!rvm64::memory::read_process_memory(proc->handle, vmcs + offsetof(vmcs->program.address + pc - 3), (uint8_t*)&regs, sizeof(uintptr_t) * 7)) {
			printf("[ERR] decoder unable to read process memory (vprog): GetLastError=0x%lx\n", GetLastError());
			return;
		}
	}

	void user_loop(win_process* proc, vm_channel* channel) {
		vmcs_t *vmcs = channel->self; 

		while (true) {
			print_decode(proc, vmcs);

			std::string cmd;

			std::cout << "> ";
			std::cin >> cmd;
			// NOTE: need a method to get user character input
			// get cmd
			// get key press
			// check key press + cmd
			// send whatever
			// read client
			// decode client
			// print decode
		}
	}
}
#endif // HYPRDBG_HPP
