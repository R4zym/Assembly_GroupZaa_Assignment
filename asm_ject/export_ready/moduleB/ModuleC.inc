; ============================================================
; ModuleC.inc - Public interface for DES Module C
; ============================================================

DES_ProcessBlock PROTO pInputBlock:DWORD, pOutputBlock:DWORD, pSubKeys:DWORD, mode:DWORD
DES_FeistelFunction PROTO pR_In:DWORD, pSubKey_In:DWORD, pOutput_Out:DWORD
