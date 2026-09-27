; =========================================================
; ModuleC.inc - Prototypes for External Modules
; =========================================================

DES_FeistelFunction PROTO pR_In:DWORD, pSubKey_In:DWORD, pOutput_Out:DWORD
DES_ProcessBlock    PROTO pInputBlock:DWORD, pOutputBlock:DWORD, pSubKeys:DWORD, mode:DWORD
DES_EncryptBuffer   PROTO pInBuf:PTR BYTE, inLen:DWORD, pOutBuf:PTR BYTE, pOutLen:PTR DWORD, pSubKeys:PTR BYTE
DES_DecryptBuffer   PROTO pInBuf:PTR BYTE, inLen:DWORD, pOutBuf:PTR BYTE, pOutLen:PTR DWORD, pSubKeys:PTR BYTE