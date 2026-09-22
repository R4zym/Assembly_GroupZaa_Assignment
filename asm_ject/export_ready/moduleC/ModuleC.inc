; ============================================================
; ModuleC.inc - Public interface for DES Module C
; ============================================================

DES_ProcessBlock PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE, DWORD
DES_FeistelFunction PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE
