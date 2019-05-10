// func cpuidAMD64(cpuidParams *uint32)
TEXT ·cpuidAMD64(SB),4,$0-8
	MOVQ cpuidParams+0(FP), R15
	MOVL 0(R15), AX
	MOVL 8(R15), CX
	CPUID
	MOVL AX, 0(R15)
	MOVL BX, 4(R15)
	MOVL CX, 8(R15)
	MOVL DX, 12(R15)
	RET
