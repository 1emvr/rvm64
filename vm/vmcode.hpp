#ifndef VMCODE_H
#define VMCODE_H
#include <stdarg.h>

#include "vmmain.hpp"
#include "vmmem.hpp"
#include "vmutils.hpp"
#include "vmcrypt.hpp"
#include "vmmu.hpp"


VM_CALL VOID Decode (_In_ const UINT32); 


VOID Opcall (
		_In_ const UINT32 Index) 
{
	UINT_PTR a = ((UINT_PTR*)DispatchTable) [Index];					
	UINT_PTR b = DecryptPtr ((UINT_PTR)a, (UINT_PTR)DKEY);	

	VOID (VM_CALL *Operation)() = (VOID (VM_CALL*)()) b;											
	Operation ();													
}


VM_CALL VOID VmExecute () {
	if (setjmp (Vmcs->Context->Branch)) { } 
	while (true) {
		INT32 Opcode = *(INT32*) Vmcs->Hdw.Pc;

		if (Opcode == RV64_RET) {
			if (! PROCESS_MEMORY_IN_BOUNDS (Vmcs->Hdw.Regs [RA])) {
				SetCsrTrap (nullptr, InstructionAccessFault, 0, 0, true);
			}
		}
		Decode (Opcode); 
		Vmcs->Hdw.Pc += 4;
	}
}

// TODO: Opcode randomization
DATA_SCN OPCODE EncodingTable [] = {
	{0b1010011, RTYPE}, {0b1000011, RTYPE}, {0b0110011, RTYPE}, {0b1000111, R4TYPE}, {0b1001011, R4TYPE}, {0b1001111, R4TYPE},
	{0b0000011, ITYPE}, {0b0001111, ITYPE}, {0b1100111, ITYPE}, {0b0010011, ITYPE}, {0b1110011, ITYPE}, {0b0011011, ITYPE},
	{0b0100011, STYPE}, {0b0100111, STYPE}, {0b1100011, BTYPE}, {0b0010111, UTYPE}, {0b0110111, UTYPE}, {0b1101111, JTYPE},
};


VMCALL VOID Decode (_In_ const UINT32 Opcode) {
	UINT8 Decoded = 0;
	UINT8 Opcode7 = Opcode & 0x7F;

	for (int idx = 0; idx < sizeof (ENCODING); idx++) {
		if (EncodingTable [idx].Mask == Opcode7) {
			Decoded = EncodingTable [idx].Type;
			break;
		}
	}
	if (! Decoded) {
		SetCsrTrap (Vmcs->Hdw.Pc, IllegalInstruction, 0, opcode, 1);
	}

	switch(Decoded) {
		case ITYPE: 
			{
				UINT8 Func3 = (Opcode >> 12) & 0x7;
				ScrWrite (UINT8, RD, (Opcode >> 7) & 0x1F);
				ScrWrite (UINT8, RS1, (Opcode >> 15) & 0x1F);

				switch(Opcode7) {
					case 0b1110011:
						{
							auto Imm = imm_i (Opcode);
							switch (Imm) {
								case 0b000000000000: { Opcall (_ECALL); break; }
								case 0b000000000001: { Opcall (_EBREAK); break; }
								default: break;
							}
							break;
						}
					case 0b0010011: 
						{
							switch(Func3) {
								case 0b000: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_ADDI); break; }
								case 0b010: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_SLTI); break; }
								case 0b011: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_SLTIU); break; }
								case 0b100: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_XORI); break; }
								case 0b110: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_ORI);  break; }
								case 0b111: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_ANDI); break; }
								case 0b001: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SLLI); break; }
								case 0b101: {
												UINT8 Func7 = (Opcode >> 25) & 0x7F; 
												switch(Func7) {
													case 0b0000000: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SRLI); break; }
													case 0b0100000: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SRAI); break; }
													default: break;
												}
											}
								default: break;
							}
							break;
						}
					case 0b0011011: 
						{
							switch(func3) {
								case 0b000: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_ADDIW); break; }
								case 0b001: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SLLIW); break; }
								case 0b101: 
											{
												UINT8 Func7 = (Opcode >> 25) & 0x7F;
												switch(Func7) {
													case 0b0000000: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SRLIW); break; }
													case 0b0100000: { ScrWrite (INT32, Imm, shamt_i (Opcode)); Opcall (_SRAIW); break; }
													default: break;
												}
											}
								default: break;
							}
							break;
						}
					case 0b0000011: 
						{
							switch(Func3) {
								case 0b000: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LB); break;  }
								case 0b001: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LH); break;  }
								case 0b010: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LW); break;  }
								case 0b100: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LBU); break; }
								case 0b101: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LHU); break; }
								case 0b110: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LWU); break; }
								case 0b011: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_LD); break;  }
								default: break;
							}
							break;
						}
					case 0b1100111:
						{
							switch(Func3) {
								case 0b000: { ScrWrite (INT32, Imm, imm_i (Opcode)); Opcall (_JALR); break; }
							}
						}
					default: break;
				}
				break;
			}

		case RTYPE: 
			{
				ScrWrite (UINT8, RD, (Opcode >> 7) & 0x1F);
				ScrWrite (UINT8, RS1, (Opcode >> 15) & 0x1F);
				ScrWrite (UINT8, RS2, (Opcode >> 20) & 0x1F);

				switch(Opcode7) {
					case 0b1010011: 
						{
							UINT8 Func7 = (Opcode >> 25) & 0x7F;
							switch(Func7) {
								case 0b0000001: { Opcall (_FADD_D); break; }
								case 0b0000101: { Opcall (_FSUB_D); break; }
								case 0b0001001: { Opcall (_FMUL_D); break; }
								case 0b0001101: { Opcall (_FDIV_D); break; }
								case 0b1111001: { Opcall (_FMV_D_X); break; }
								case 0b0100000: 
												{
													UINT8 FcvtMask = (Opcode >> 20) & 0x1F;
													switch(FcvtMask) {
														case 0b00001: { Opcall (_FCVT_S_D); break; }
														default: break;
													}
													break;
												}
								case 0b0100001: 
												{
													UINT8 FcvtMask = (Opcode >> 20) & 0x1F;
													switch(FcvtMask) {
														case 0b00000: { Opcall (_FCVT_D_S); break; }
														default: break;
													}
													break;
												}
								case 0b1100001: 
												{
													UINT8 FcvtMask = (Opcode >> 20) & 0x1F;
													switch(FcvtMask) {
														case 0b00000: { Opcall (_FCVT_W_D); break; }
														case 0b00001: { Opcall (_FCVT_WU_D); break; }
														default: break;
													}
													break;
												}
								case 0b1101001: 
												{
													UINT8 FcvtMask = (Opcode >> 20) & 0x1F;
													switch(FcvtMask) {
														case 0b00000: { Opcall (_FCVT_D_W); break; }
														case 0b00001: { Opcall (_FCVT_D_WU); break; }
														default: break;
													}
													break;
												}
								case 0b0010001: 
												{
													UINT8 Func3 = (Opcode >> 12) & 0x7;
													switch(Func3) {
														case 0b000: { Opcall (_FSGNJ_D); break; }
														case 0b001: { Opcall (_FSGNJN_D); break; }
														case 0b010: { Opcall (_FSGNJX_D); break; }
														default: break;
													}
													break;
												}
								case 0b0010101: 
												{
													UINT8 Func3 = (Opcode >> 12) & 0x7;
													switch(Func3) {
														case 0b000: { Opcall (_FMIN_D); break; }
														case 0b001: { Opcall (_FMAX_D); break; }
														default: break;
													}
													break;
												}
								case 0b1010001: 
												{
													UINT8 Func3 = (Opcode >> 12) & 0x7;
													switch(Func3) {
														case 0b010: { Opcall (_FEQ_D); break; }
														case 0b001: { Opcall (_FLT_D); break; }
														case 0b000: { Opcall (_FLE_D); break; }
														default: break;
													}
													break;
												}
								case 0b1110001: 
												{
													UINT8 Func3 = (Opcode >> 12) & 0x7;
													switch(Func3) {
														case 0b001: { Opcall (_FCLASS_D); break; }
														default: break;
													}
													break;
												}
								default: break;
							}
							break;
						}
					case 0b0101111: 
						{
							UINT8 Func7 = (Opcode >> 25) & 0x7F;
							UINT8 Func5 = (Func7 >> 2) & 0x1F;
							UINT8 Func3 = (Opcode >> 12) & 0x7;

							switch(Func3) {
								case 0b010: 
									{
										switch(Func5) {
											case 0b00010: { Opcall (_LRW); break; }
											case 0b00011: { Opcall (_SCW); break; }
											case 0b00001: { Opcall (_AMOSWAP_W); break; }
											case 0b00000: { Opcall (_AMOADD_W); break; }
											case 0b00100: { Opcall (_AMOXOR_W); break; }
											case 0b01100: { Opcall (_AMOAND_W); break; }
											case 0b01000: { Opcall (_AMOOR_W); break; }
											case 0b10000: { Opcall (_AMOMIN_W); break; }
											case 0b10100: { Opcall (_AMOMAX_W); break; }
											case 0b11000: { Opcall (_AMOMINU_W); break; }
											case 0b11100: { Opcall (_AMOMAXU_W); break; }
											default: break;
										}
										break;
									}
								case 0b011: 
									{
										switch(Func5) {
											case 0b00010: { Opcall (_LRD); break; }
											case 0b00011: { Opcall (_SCD); break; }
											case 0b00001: { Opcall (_AMOSWAP_D); break; }
											case 0b00000: { Opcall (_AMOADD_D); break; }
											case 0b00100: { Opcall (_AMOXOR_D); break; }
											case 0b01100: { Opcenvironment_call_nativeall (_AMOAND_D); break; }
											case 0b01000: { Opcall (_AMOOR_D); break; }
											case 0b10000: { Opcall (_AMOMIN_D); break; }
											case 0b10100: { Opcall (_AMOMAX_D); break; }
											case 0b11000: { Opcall (_AMOMINU_D); break; }
											case 0b11100: { Opcall (_AMOMAXU_D); break; }
											default: break;
										}
										break;
									}
								default: break;
							}
							break;
						}
					case 0b0111011: 
						{
							UINT8 Func7 = (Opcode >> 25) & 0x7F;
							UINT8 Func3 = (Opcode >> 12) & 0x7;

							switch(Func3) {
								case 0b000: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_ADDW); break; }
											case 0b0100000: { Opcall (_SUBW); break; }
											case 0b0000001: { Opcall (_MULW); break; }
											default: break;
										}
										break;
									}
								case 0b101: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_SRLW); break; }
											case 0b0100000: { Opcall (_SRAW); break; }
											case 0b0000001: { Opcall (_DIVUW); break; }
											default: break;
										}
										break;
									}
								case 0b001: { Opcall (_SLLW); break; }
								case 0b100: { Opcall (_DIVW); break; }
								case 0b110: { Opcall (_REMW); break; }
								case 0b111: { Opcall (_REMUW); break; }
								default: break;
							}
							break;
						}
					case 0b0110011: 
						{
							UINT8 Func7 = (Opcode >> 25) & 0x7F;
							UINT8 Func3 = (Opcode >> 12) & 0x7;

							switch(Func3) {
								case 0b000: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_ADD); break; }
											case 0b0100000: { Opcall (_SUB); break; }
											case 0b0000001: { Opcall (_MUL); break; }
											default: break;
										}
										break;
									}
								case 0b001: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_SLL); break; }
											case 0b0000001: { Opcall (_MULH); break; }
											default: break;
										}
										break;
									}
								case 0b010: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_SLT); break; }
											case 0b0000001: { Opcall (_MULHSU); break; }
											default: break;
										}
										break;
									}
								case 0b011: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_SLTU); break; }
											case 0b0000001: { Opcall (_MULHU); break; }
											default: break;
										}
										break;
									}
								case 0b100: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_XOR); break; }
											case 0b0000001: { Opcall (_DIV); break; }
											default: break;
										}
										break;
									}
								case 0b101: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_SRL); break; }
											case 0b0100000: { Opcall (_SRA); break; }
											case 0b0000001: { Opcall (_DIVU); break; }
											default: break;
										}
										break;
									}
								case 0b110: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_OR); break; }
											case 0b0000001: { Opcall (_REM); break; }
											default: break;
										}
										break;
};
									}
								case 0b111: 
									{
										switch(Func7) {
											case 0b0000000: { Opcall (_AND); break; }
											case 0b0000001: { Opcall (_REMU); break; }
											default: break;
										}
										break;
									}
								default: 
									break;
							}
							break;
						}
					default: 
						break;
				}
				break;
			}

		case STYPE: 
			{
				UINT8 Func3 = (Opcode >> 12) & 0x7;

				ScrWrite (UINT8, RS2, (Opcode >> 20) & 0x1F);
				ScrWrite (UINT8, RS1, (Opcode >> 15) & 0x1F);
				ScrWrite (INT32, IMM, imm_s (Opcode));

				switch(Opcode7) {
					case 0b0100011: 
						{
							switch(Func3) {
								case 0b000: { Opcall (_SB); break; }
								case 0b001: { Opcall (_SH); break; }
								case 0b010: { Opcall (_SW); break; }
								case 0b011: { Opcall (_SD); break; }
								default: break;
							}
							break;
						}
					case 0b0100111: {
										switch(Func3) {
											case 0b010: { Opcall (_FSW); break; }
											case 0b011: { Opcall (_FSD); break; }
											default: break;
										}
										break;
									}
					default: break;
				}
				break;
			}

		case BTYPE: 
			{
				UINT8 Func3 = (Opcode >> 12) & 0x7;

				ScrWrite (UINT8, RS2, (Opcode >> 20) & 0x1F);
				ScrWrite (UINT8, RS1, (Opcode >> 15) & 0x1F);
				ScrWrite (INT32, IMM, imm_b (Opcode));

				switch(Func3) {
					case 0b000: { Opcall (_BEQ); break; }
					case 0b001: { Opcall (_BNE); break; }
					case 0b100: { Opcall (_BLT); break; }
					case 0b101: { Opcall (_BGE); break; }
					case 0b110: { Opcall (_BLTU); break; }
					case 0b111: { Opcall (_BGEU); break; }
					default: break;
				}
				break;
			}

		case UTYPE: 
			{
				ScrWrite (UINT8, RD, (Opcode >> 7) & 0x1F);
				ScrWrite (INT32, IMM, imm_u (Opcode));

				switch(Opcode7) {
					case 0b0110111: { Opcall (_LUI); break; }
					case 0b0010111: { Opcall (_AUIPC); break; }
					default: break;
				}
				break;
			}

		case JTYPE:
			{
				ScrWrite (UINT8, RD, (Opcode >> 7) & 0x1F);
				ScrWrite (INT32, IMM, imm_j (Opcode));

				switch(Opcode7) {
					case 0b1101111: { Opcall (_JAL); break; }
					default: break;
				}
				break;
			}

		default: {
					 SetCsrTrap (Vmcs->Hdw.Pc, IllegalInstruction, 0, Opcode, 1);
					 break;
				 }
	}
}

VMCALL void lrw () {
	UINT8 _rd = 0, _rs1 = 0; UINT_PTR address = 0; INT32 value = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (UINT_PTR, address, _rs1);

	MemRead (INT32, value, address);
	RegWrite (INT32, _rd, value);
}

VMCALL void lrd () {
	UINT8 _rd = 0, _rs1 = 0; UINT_PTR address = 0; INT64 value = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (UINT_PTR, address, _rs1);

	MemRead (INT64, value, address);
	RegWrite (INT64, _rd, value);
}

VMCALL void fmv_d_x () {
	UINT8 _rd = 0, _rs1 = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, v1);
}

VMCALL void fcvt_s_d () {
	UINT8 _rd = 0, _rs1 = 0; float v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (double, v1, _rs1);
	RegWrite (float, _rd, v1);
}

VMCALL void fcvt_d_s () {
	UINT8 _rd = 0, _rs1 = 0; double v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (float, v1, _rs1);
	RegWrite (double, _rd, v1);
}

VMCALL void fcvt_w_d () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (double, v1, _rs1);
	RegWrite (INT32, _rd, v1);
}

VMCALL void fcvt_wu_d () {
	UINT8 _rd = 0, _rs1 = 0; UINT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (double, v1, _rs1);
	RegWrite (UINT32, _rd, v1);
}

VMCALL void fcvt_d_w () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (INT32, v1, _rs1);
	RegWrite (double, _rd, v1);
}

VMCALL void fcvt_d_wu () {
	UINT8 _rd = 0, _rs1 = 0; UINT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (UINT32, v1, _rs1);
	RegWrite (double, _rd, v1);
}

		// NOTE: maybe not even real...
VMCALL void fclass_d () {
	UINT8 _rd = 0, _rs1 = 0; double v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);

	RegRead (double, v1, _rs1);
	converter.d = v1;

	const UINT64 exponent = (converter.u >> 52) & 0x7FF;
	const UINT64 fraction = converter.u & 0xFFFFFFFFFFFFF;
	const UINT64 sign = converter.u >> 63;

	if (exponent == 0x7FF) {
		if (fraction == 0) {
			if (sign == 0) {
				RegWrite (int, _rd, 0x7); // +inf
			} else {
				RegWrite (int, _rd, 0x0); // -inf
			}
		} else {
			if (fraction & (1LL << 51)) {
				RegWrite (int, _rd, 0x8); // quiet NaN
			} else {
				RegWrite (int, _rd, 0x9); // signaling NaN
			}
		}
	} else if (exponent == 0) {
		if (fraction == 0) {
			if (sign == 0) {
				RegWrite (int, _rd, 0x4); // +0
			} else {
				RegWrite (int, _rd, 0x3); // -0
			}
		} else {
			if (sign == 0) {
				RegWrite (int, _rd, 0x5); // +subnormal
			} else {
				RegWrite (int, _rd, 0x2); // -subnormal
			}
		}
	} else {
		if (sign == 0) {
			RegWrite (int, _rd, 0x6); // +normal
		} else {
			RegWrite (int, _rd, 0x1); // -normal
		}
	}
}

// NOTE: immediates are always signed unless there's a bitwise operation
VMCALL void addi () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, (v1 + _imm));
}

VMCALL void slti () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, ((v1 < _imm) ? 1 : 0));
}

VMCALL void sltiu () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT64, v1, _rs1);
	RegWrite (UINT64, _rd, ((v1 < (UINT32)_imm) ? 1 : 0));
}

VMCALL void xori () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, (v1 ^ _imm));
}

VMCALL void ori () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, (v1 | _imm));
}

VMCALL void andi () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (INT32, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT64, v1, _rs1);
	RegWrite (INT64, _rd, (v1 & _imm));
}

VMCALL void slli () {
	UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (UINT64, v1, _rs1);
	RegWrite (UINT64, _rd, (v1 << (_shamt & 0x1F)));
}

VMCALL void srli () {
	UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; UINT64 v1 = 0; 

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (UINT64, v1, _rs1);
	RegWrite (UINT64, _rd, v1 >> (_shamt & 0x1F));
}

VMCALL void srai () {
	UINT8 _rd = 0, _rs1 = 0; UINT32 _shamt = 0; UINT64 v1 = 0; 

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (UINT64, v1, _rs1);
	RegWrite (UINT64, _rd, v1 >> (_shamt & 0x1F));
}

VMCALL void addiw () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; INT32 _imm = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (INT32, v1, _rs1);
	RegWrite (INT32, _rd, v1 + _imm);
}

VMCALL void slliw () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (INT32, v1, _rs1);

	if ((_shamt >> 5) != 0) {
		SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
	}

	RegWrite (INT32, _rd, v1 << (_shamt & 0x1F));
}

VMCALL void srliw () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (INT32, v1, _rs1);

	if ((_shamt >> 5) != 0) {
		SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
	}

	RegWrite (INT32, _rd, v1 >> (_shamt & 0x1F));
}

VMCALL void sraiw () {
	UINT8 _rd = 0, _rs1 = 0; INT32 v1 = 0; UINT32 _shamt = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT32, _shamt, imm);

	RegRead (INT32, v1, _rs1);

	if ((_shamt >> 5) != 0) {
		SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, (UINT64)Vmcs->Gpr->Scratch, 1);
	}
	// TODO: this may be wrong to mask
	RegWrite (INT32, _rd, v1 >> (_shamt & 0x1F));
}

VMCALL void lb () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT8 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (INT8, v1, address);
	RegWrite (INT8, _rd, v1);
}

VMCALL void lh () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT16 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (INT16, v1, address);
	RegWrite (INT16, _rd, v1);
}

VMCALL void lw () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (INT32, v1, address);
	RegWrite (INT32, _rd, v1);
}

VMCALL void lbu () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT8 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (UINT8, v1, address);
	RegWrite (UINT8, _rd, v1);
}

VMCALL void lhu () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT16 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (UINT16, v1, address);
	RegWrite (UINT16, _rd, v1);
}

VMCALL void lwu () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT32 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (UINT32, v1, address);
	RegWrite (UINT32, _rd, v1);
}

VMCALL void ld () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0; INT64 v1 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;

	MemRead (INT64, v1, address);
	RegWrite (INT64, _rd, v1);
}

VMCALL void jalr () {
	UINT8 _rd = 0, _rs1 = 0; INT32 _imm = 0; UINT_PTR address = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	address += (INT_PTR)_imm;
	address &= ~((INT_PTR)1);

	RegWrite (UINT_PTR, _rd, Vmcs->Hdw.Pc);
	Vmcs->Hdw.Pc = address;

	if (auto HostMem = MemoryCheck (Vmcs->Hdw.Pc)) {
		Vmcs->Hdw.Pc = (UINT_PTR)HostMem;
		SetCsrTrap (Vmcs->Hdw.Pc, EnvExecute, 0, 0, 0);
	}
	if (!PROCESS_MEMORY_IN_BOUNDS(Vmcs->Hdw.Pc)) {
		SetCsrTrap (Vmcs->Hdw.Pc, NativeCall, 0, 0, 0);
	}
}

VMCALL void flq () {
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void fence () {
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void fence_i () {
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void ecall () {
	/*
	   Description
	   Make a request to the supporting execution environment.
	   When executed in U-mode, S-mode, or M-mode, it generates an environment-call-from-U-mode exception,
	   environment-call-from-S-mode exception, or environment-call-from-M-mode exception, respectively, and performs no other operation.

	   Implementation
	   RaiseException(EnvironmentCall)

*/
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void ebreak () {
	/*
	   Description
	   Used by debuggers to cause control to be transferred back to a debugging environment.
	   It generates a breakpoint exception and performs no other operation.

	   Implementation
	   RaiseException(Breakpoint)
	   */
	__debugbreak();
}

		// NOTE: csr operations aren't needed rn.
VMCALL void csrrw () {
	/*
	   Description
	   Atomically swaps values in the CSRs and integer registers.
	   CSRRW reads the old value of the CSR, zero-extends the value to XLEN bits, then writes it to integer register _rd.
	   The initial value in _rs1 is written to the CSR.
	   If _rd=x0, then the instruction shall not read the CSR and shall not cause any of the side effects that might occur on a CSR read.

	   Implementation
	   t = CSRs[csr]; CSRs[csr] = x[_rs1]; x[_rd] = t
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void csrrs () {
	/*
	   Description
	   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
	   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be set in the CSR.
	   Any bit that is high in _rs1 will cause the corresponding bit to be set in the CSR, if that CSR bit is writable.
	   Other bits in the CSR are unaffected (though CSRs might have side effects when written).

	   Implementation
	   t = CSRs[csr]; CSRs[csr] = t | x[_rs1]; x[_rd] = t
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void csrrc () {
	/*
	   Description
	   Reads the value of the CSR, zero-extends the value to XLEN bits, and writes it to integer register _rd.
	   The initial value in integer register _rs1 is treated as a bit mask that specifies bit positions to be cleared in the CSR.
	   Any bit that is high in _rs1 will cause the corresponding bit to be cleared in the CSR, if that CSR bit is writable.
	   Other bits in the CSR are unaffected.

	   Implementation
	   t = CSRs[csr]; CSRs[csr] = t &~x[_rs1]; x[_rd] = t
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void csrrwi () {
	/*
	   Description
	   Update the CSR using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

	   Implementation
	   x[_rd] = CSRs[csr]; CSRs[csr] = zimm
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void csrrsi () {
	/*
	   Description
	   Set CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

	   Implementation
	   t = CSRs[csr]; CSRs[csr] = t | zimm; x[_rd] = t
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void csrrci () {
	/*
	   Description
	   Clear CSR bit using an XLEN-bit value obtained by zero-extending a 5-bit unsigned immediate (uimm[4:0]) field encoded in the _rs1 field.

	   Implementation
	   t = CSRs[csr]; CSRs[csr] = t &~zimm; x[_rd] = t
	   */
	SetCsrTrap (Vmcs->Hdw.Pc, InstructionIllegal, 0, 0, 1);
}

VMCALL void scw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 value = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	MemRead (UINT_PTR, address, _rs1);
	RegRead (INT32, value, _rs2);

	if (rvm64::memory::vm_check_load_rsv(0, address)) {
		rvm64::memory::vm_set_load_rsv(0, address);

		MemWrite (INT32, address, value);
		RegWrite (INT32, _rd, 0);

		rvm64::memory::vm_clear_load_rsv(0);
	} else {
		RegWrite (INT32, _rd, 1);
	}
}

VMCALL void scd () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 value = 0; UINT_PTR address = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, value, _rs2);

	if (!rvm64::memory::vm_check_load_rsv(0, address)) {
		rvm64::memory::vm_set_load_rsv(0, address);

		MemWrite (INT64, address, value);
		RegWrite (INT64, _rd, 0);

		rvm64::memory::vm_clear_load_rsv(0);

	} else {
		RegWrite (INT64, _rd, 1);
	}
}

VMCALL void fadd_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (float, v1, _rs1);
	RegRead (float, v2, _rs2);

	RegWrite (float, _rd, (v1 + v2));
}

VMCALL void fsub_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (float, v1, _rs1);
	RegRead (float, v2, _rs2);

	RegWrite (float, _rd, (v1 - v2));
}

VMCALL void fmul_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (float, v1, _rs1);
	RegRead (float, v2, _rs2);

	RegWrite (float, _rd, (v1 * v2));
}

VMCALL void fdiv_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; float v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (float, v1, _rs1);
	RegRead (float, v2, _rs2);

	RegWrite (float, _rd, (v1 / v2));
}

VMCALL void fsgnj_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT64, v1, _rs1);
	RegRead (INT64, v2, _rs2);

	INT64 s2 = (v2 >> 63) & 1;

	v1 &= ~(1LL << 63);
	v1 |= (s2 << 63);

	RegWrite (INT64, _rd, v1);
}

VMCALL void fsgnjn_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT64, v1, _rs1);
	RegRead (INT64, v2, _rs2);

	INT64 s2 = ((v2 >> 63) & 1) ^ 1;

	v1 &= ~(1LL << 63);
	v1 |= (s2 << 63);

	RegWrite (INT64, _rd, v1);
}

VMCALL void fsgnjx_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT64, v1, _rs1);
	RegRead (INT64, v2, _rs2);

	INT64 s1 = (v1 >> 63) & 1;
	INT64 s2 = (v2 >> 63) & 1;

	v1 &= ~(1LL << 63);
	v1 |= ((s1 ^ s2) << 63);

	RegWrite (INT64, _rd, v1);
}

VMCALL void fmin_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (double, v1, _rs1);
	RegRead (double, v2, _rs2);

	if (is_nan(v1)) {
		RegWrite (double, _rd, v2);
	} else if (is_nan(v2)) {
		RegWrite (double, _rd, v1);
	} else {
		RegWrite (double, _rd, (v1 > v2) ? v2 : v1);
	}
}

VMCALL void fmax_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (double, v1, _rs1);
	RegRead (double, v2, _rs2);

	if (is_nan(v1)) {
		RegWrite (double, _rd, v2);
	} else if (is_nan(v2)) {
		RegWrite (double, _rd, v1);
	} else {
		RegWrite (double, _rd, (v1 > v2) ? v1 : v2);
	}
}

VMCALL void feq_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (double, v1, _rs1);
	RegRead (double, v2, _rs2);

	if (is_nan(v1) || is_nan(v2)) {
		RegWrite (bool, _rd, false);
		return;
	}

	RegWrite (bool, _rd, (v1 == v2));
}

VMCALL void flt_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (double, v1, _rs1);
	RegRead (double, v2, _rs2);

	if (is_nan(v1) || is_nan(v2)) {
		RegWrite (bool, _rd, false);
		return;
	}

	RegWrite (bool, _rd, (v1 < v2));
}

VMCALL void fle_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; double v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (double, v1, _rs1);
	RegRead (double, v2, _rs2);

	if (is_nan(v1) || is_nan(v2)) {
		RegWrite (bool, _rd, false);
		return;
	}

	RegWrite (bool, _rd, (v1 <= v2));
}

VMCALL void addw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT64, _rd, (INT64)(v1 + v2));
}

VMCALL void subw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT64, _rd, (INT64)(v1 - v2));
}

VMCALL void mulw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT64, _rd, (INT64)(v1 * v2));
}

VMCALL void srlw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 >> (v2 & 0x1F)));
}

VMCALL void sraw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 >> (v2 & 0x1F)));
}

VMCALL void divuw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (UINT32, _rd, (v1 / v2));
}

VMCALL void sllw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 << (v2 & 0x1F)));
}

VMCALL void divw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 / v2));
}

VMCALL void remw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 % v2));
}

VMCALL void remuw () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (UINT32, _rd, (v1 % v2));
}

VMCALL void add () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 + v2));
}

VMCALL void sub () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 - v2));
}

VMCALL void mul () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	RegWrite (INT32, _rd, (v1 * v2));
}

VMCALL void sll () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT32 v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT32, _rs1, v1);
	RegRead (INT32, _rs2, v2);

	RegWrite (INT32, _rd, (v1 << (v2 & 0x1F)));
}

VMCALL void mulh () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT_PTR, v1, _rs1);
	RegRead (INT_PTR, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
	INT64 result = (INT64)v1 * (INT64)v2;
	RegWrite (INT32, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
	__int128 result = (__int128)v1 * (__int128)v2;
	RegWrite (INT64, _rd, (result >> 64));

#endif
}

VMCALL void slt () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT_PTR, v1, _rs1);
	RegRead (INT_PTR, v2, _rs2);

	RegWrite (INT_PTR, _rd, ((v1 < v2) ? 1 : 0));
}

VMCALL void mulhsu () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0; UINT_PTR v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);environment_call_native

	RegRead (INT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

#if UINTPTR_MAX == 0xFFFFFFFF
	INT64 result = (INT64)(INT32)v1 * (UINT64)(UINT32)v2;
	RegWrite (INT32, _rd, (result >> 32));

#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
	__int128 result = (__int128) (INT64) v1 * (__uint128_t) (UINT64) v2;
	RegWrite (INT64, _rd, (result >> 64));
#endif
}

VMCALL void sltu () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	RegWrite (UINT_PTR, _rd, ((v1 < v2) ? 1 : 0));
}

VMCALL void mulhu () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	UINT_PTR result = v1 * v2;

#if UINTPTR_MAX == 0xFFFFFFFF
	RegWrite (UINT_PTR, _rd, (result >> 16));
#elif UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
	RegWrite (UINT_PTR, _rd, (result >> 32));
#endif
}

VMCALL void xor () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	RegWrite (UINT_PTR, _rd, (v1 ^ v2));
}

VMCALL void div () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	RegWrite (UINT_PTR, _rd, (v1 / v2));
}
environment_call_native
VMCALL void srl () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (UINT_PTR, _rd, (v1 >> (v2 & 0x1F)));
}

VMCALL void sra () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0; UINT32 v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT_PTR, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	RegWrite (INT_PTR, _rd, (v1 >> (v2 & 0x1F)));
}

VMCALL void divu () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	if (v2 == 0) {
		RegWrite (UINT_PTR, _rd, 0);
	} else {
		RegWrite (UINT_PTR, _rd, (v1 / v2));
	}
}

VMCALL void or () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT_PTR, _rs1, v1);
	RegRead (INT_PTR, _rs2, v2);

	RegWrite (INT_PTR, _rd, (v1 | v2));
}

VMCALL void rem () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; INT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (INT_PTR, v1, _rs1);
	RegRead (INT_PTR, v2, _rs2);

	if (v2 == 0) {
		RegWrite (INT_PTR, _rd, 0);
	} else {
		RegWrite (INT_PTR, _rd, (v1 % v2));
	}
}

VMCALL void and () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	RegWrite (UINT_PTR, _rd, (v1 & v2));
}

VMCALL void remu () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, v1, _rs1);
	RegRead (UINT_PTR, v2, _rs2);

	if (v2 == 0) {
		RegWrite (UINT_PTR, _rd, 0);
	} else {
		RegWrite (UINT_PTR, _rd, (v1 % v2));
	}
}

VMCALL void amoswap_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);

	MemRead (INT64, v1, address);
	MemWrite (INT64, address, v2);
	RegWrite (INT64, _rd, v1);

}

VMCALL void amoadd_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 + v2));
	RegWrite (INT64, _rd, v1);

}

VMCALL void amoxor_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 ^ v2));
	RegWrite (INT64, _rd, v1);

}

VMCALL void amoand_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 & v2));
	RegWrite (INT64, _rd, v1);

}

VMCALL void amoor_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 | v2));
	RegWrite (INT64, _rd, v1);

}

VMCALL void amomin_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 < v2 ? v1 : v2));
	RegWrite (UINT64, _rd, v1);

}

VMCALL void amomax_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT64, v2, _rs2);


	MemRead (INT64, v1, address);
	MemWrite (INT64, address, (v1 < v2 ? v2 : v1));
	RegWrite (INT64, _rd, v1);

}

VMCALL void amominu_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, _rs1, address);
	RegRead (UINT64, _rs2, v2);


	MemRead (UINT64, v1, address);
	MemWrite (UINT64, address, (v1 < v2 ? v1 : v2));
	RegWrite (UINT64, _rd, v1);

}

VMCALL void amomaxu_d () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT64 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT64, v2, _rs2);

	MemRead (UINT64, v1, address);

	MemWrite (UINT64, address, (v1 < v2 ? v2 : v1));
	RegWrite (UINT64, _rd, v1);
}

VMCALL void amoswap_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);

	MemRead (INT32, v1, address);

	MemWrite (INT32, address, v2);
	RegWrite (INT32, _rd, v1);
}

VMCALL void amoadd_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);

	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 + v2));

	RegWrite (INT32, _rd, v1);
}

VMCALL void amoxor_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);

	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 ^ v2));

	RegWrite (INT32, _rd, v1);
}

VMCALL void amoand_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);


	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 & v2));
	RegWrite (INT32, _rd, v1);

}

VMCALL void amoor_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);


	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 | v2));
	RegWrite (INT32, _rd, v1);

}

VMCALL void amomin_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);


	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 < v2 ? v1 : v2));
	RegWrite (INT32, _rd, v1);

}

VMCALL void amomax_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; INT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT32, v2, _rs2);


	MemRead (INT32, v1, address);
	MemWrite (INT32, address, (v1 < v2 ? v2 : v1));
	RegWrite (INT32, _rd, v1);

}

VMCALL void amominu_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT32, v2, _rs2);


	MemRead (UINT32, v1, address);
	MemWrite (UINT32, address, (v1 < v2 ? v1 : v2));
	RegWrite (UINT32, _rd, v1);

}

VMCALL void amomaxu_w () {
	UINT8 _rd = 0, _rs1 = 0, _rs2 = 0; UINT_PTR address = 0; UINT32 v1 = 0, v2 = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT32, v2, _rs2);


	MemRead (UINT32, v1, address);
	MemWrite (UINT32, address, (v1 < v2 ? v2 : v1));
	RegWrite (UINT32, _rd, v1);

}

VMCALL void lui () {
	UINT8 _rd = 0; INT32 _imm = 0;

	ScrRead (UINT32, _rd, rd);
	ScrRead (INT32, _imm, imm);
	RegWrite (INT32, _rd, _imm);
}

VMCALL void auipc () {
	UINT8 _rd = 0; INT32 _imm = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (INT32, _imm, imm);
	RegWrite (INT64, _rd, (INT64)Vmcs->Hdw.Pc + _imm);
}

VMCALL void jal () {
	UINT8 _rd = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rd, rd);
	ScrRead (INT_PTR, offset, imm);
	RegWrite (UINT_PTR, _rd, Vmcs->Hdw.Pc + 4);

	Vmcs->Hdw.Pc += offset;
	SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
}

VMCALL void beq () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	if (v1 == v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void bne () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	if (v1 != v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void blt () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	if (v1 < v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void bge () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (INT32, v1, _rs1);
	RegRead (INT32, v2, _rs2);

	if (v1 >= v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void bltu () {
	UINT8 _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (UINT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	if (v1 < v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void bgeu () {
	UINT8 _rs1 = 0, _rs2 = 0; UINT32 v1 = 0, v2 = 0; INT_PTR offset = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT_PTR, offset, imm);

	RegRead (UINT32, v1, _rs1);
	RegRead (UINT32, v2, _rs2);

	if (v1 >= v2) {
		Vmcs->Hdw.Pc += offset;
		SetCsrTrap (nullptr, EnvBranch, 0, 0, 0);
	}
}

VMCALL void sb () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT8 v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (INT8, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (UINT8, address, v1);
}

VMCALL void sh () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT16 v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT16, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (UINT16, address, v1);
}

VMCALL void sw () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT32 v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT32, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (UINT32, address, v1);
}

VMCALL void sd () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; UINT64 v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT64, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (UINT64, address, v1);
}

VMCALL void fsw () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; float v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (float, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (float, address, v1);
}

VMCALL void fsd () {
	UINT8 _rs1 = 0, _rs2 = 0; INT32 _imm = 0; UINT_PTR address = 0; double v1 = 0;

	ScrRead (UINT8, _rs1, rs1);
	ScrRead (UINT8, _rs2, rs2);
	ScrRead (INT32, _imm, imm);

	RegRead (UINT_PTR, address, _rs1);
	RegRead (UINT64, v1, _rs2);

	address += (INT_PTR)_imm;
	MemWrite (double, address, v1);
}

namespace r4type {

};


#ifdef
#define ENCRYPT (op) EncryptPtr ((UINT_PTR)(op), (UINT_PTR)DKEY)
#else
#define ENCRYPT (op) 
#endif

DATA_SCN const UINT_PTR DispatchTable [256] = {
    // ITYPE
    ENCRYPT (addi), 		ENCRYPT (slti),
    ENCRYPT (sltiu), 		ENCRYPT (xori),
    ENCRYPT (ori), 			ENCRYPT (andi),
    ENCRYPT (slli), 		ENCRYPT (srli),
    ENCRYPT (srai), 		ENCRYPT (addiw),
    ENCRYPT (slliw), 		ENCRYPT (srliw),
    ENCRYPT (sraiw), 		ENCRYPT (lb),
    ENCRYPT (lh), 			ENCRYPT (lw),
    ENCRYPT (lbu), 			ENCRYPT (lhu),
    ENCRYPT (lwu), 			ENCRYPT (ld),
    ENCRYPT (flq), 			ENCRYPT (fence),
    ENCRYPT (fence_i), 		ENCRYPT (jalr),
    ENCRYPT (ecall), 		ENCRYPT (ebreak),
    ENCRYPT (csrrw), 		ENCRYPT (csrrs),
    ENCRYPT (csrrc), 		ENCRYPT (csrrwi),
    ENCRYPT (csrrsi), 		ENCRYPT (csrrci),
    ENCRYPT (fclass_d), 	ENCRYPT (lrw),
    ENCRYPT (lrd), 			ENCRYPT (fmv_d_x),
    ENCRYPT (fcvt_s_d), 	ENCRYPT (fcvt_d_s),
    ENCRYPT (fcvt_w_d), 	ENCRYPT (fcvt_wu_d),
    ENCRYPT (fcvt_d_w), 	ENCRYPT (fcvt_d_wu),

    // RTYPE
    ENCRYPT (fadd_d), 		ENCRYPT (fsub_d),
    ENCRYPT (fmul_d), 		ENCRYPT (fdiv_d),
    ENCRYPT (fsgnj_d), 		ENCRYPT (fsgnjn_d),
    ENCRYPT (fsgnjx_d), 	ENCRYPT (fmin_d),
    ENCRYPT (fmax_d), 		ENCRYPT (feq_d),
    ENCRYPT (flt_d), 		ENCRYPT (fle_d),
    ENCRYPT (scw), 			ENCRYPT (amoswap_w),
    ENCRYPT (amoadd_w), 	ENCRYPT (amoxor_w),
    ENCRYPT (amoand_w), 	ENCRYPT (amoor_w),
    ENCRYPT (amomin_w), 	ENCRYPT (amomax_w),
    ENCRYPT (amominu_w), 	ENCRYPT (amomaxu_w),
    ENCRYPT (scd), 			ENCRYPT (amoswap_d),
    ENCRYPT (amoadd_d), 	ENCRYPT (amoxor_d),
    ENCRYPT (amoand_d), 	ENCRYPT (amoor_d),
    ENCRYPT (amomin_d), 	ENCRYPT (amomax_d),
    ENCRYPT (amominu_d), 	ENCRYPT (amomaxu_d),
    ENCRYPT (addw), 		ENCRYPT (subw),
    ENCRYPT (mulw), 		ENCRYPT (srlw),
    ENCRYPT (sraw), 		ENCRYPT (divuw),
    ENCRYPT (sllw), 		ENCRYPT (divw),
    ENCRYPT (remw), 		ENCRYPT (remuw),
    ENCRYPT (add), 			ENCRYPT (sub),
    ENCRYPT (mul), 			ENCRYPT (sll),
    ENCRYPT (mulh), 		ENCRYPT (slt),
    ENCRYPT (mulhsu), 		ENCRYPT (sltu),
    ENCRYPT (mulhu), 		ENCRYPT (xor),
    ENCRYPT (div), 			ENCRYPT (srl),
    ENCRYPT (sra), 			ENCRYPT (divu),
    ENCRYPT (or), 			ENCRYPT (rem),
    ENCRYPT (and), 			ENCRYPT (remu),

    // STYPE
    ENCRYPT (sb), 	ENCRYPT (sh),
    ENCRYPT (sw), 	ENCRYPT (sd),
    ENCRYPT (fsw), 	ENCRYPT (fsd),

    // BTYPE
    ENCRYPT (beq), 	ENCRYPT (bne),
    ENCRYPT (blt), 	ENCRYPT (bge),
    ENCRYPT (bltu), ENCRYPT (bgeu),

    // UTYPE/JTYPE
    ENCRYPT (lui), ENCRYPT (auipc),
    ENCRYPT (jal)


#endif // VMCODE_H
