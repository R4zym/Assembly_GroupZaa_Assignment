TITLE DES Module C - 16-Round Feistel Core Engine & ECB Engine (Fixed)

.386
.model flat, stdcall
.stack 4096
INCLUDE C:\Irvine\Irvine32.inc
INCLUDE ModuleB.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data

; =========================================================
; CONSTANTS & MESSAGES
; =========================================================
msgTitle        BYTE "=== DES Module C Engine Test (NIST Vector) ===", 0Dh, 0Ah, 0
msgPlain        BYTE "Plaintext  : ", 0
msgKey          BYTE "Key        : ", 0
msgEncrypted    BYTE "Ciphertext : ", 0
msgDecrypted    BYTE "Decrypted  : ", 0
msgPass         BYTE "[SUCCESS] NIST Test Vector Passed!", 0Dh, 0Ah, 0
msgFail         BYTE "[FAILED] NIST Test Vector Failed!", 0Dh, 0Ah, 0

; Test Vector  NIST (FIPS 46-3 Test Vector)
testPlaintext   BYTE 001h, 023h, 045h, 067h, 089h, 0ABh, 0CDh, 0EFh
testKey         BYTE 013h, 034h, 057h, 079h, 09Bh, 0BCh, 0DFh, 0F1h
expectedCipher  BYTE 085h, 0E8h, 013h, 054h, 00Fh, 00Ah, 0B4h, 005h

; Buffer 
cipherBuffer    BYTE 8 DUP(0)
decryptedBuffer BYTE 8 DUP(0)

; Subkeys 16  ( 6  = 6 bytes,  96 bytes)
SubKeys         BYTE 96 DUP(0)


; =========================================================
; DES PERMUTATION TABLES (1-indexed  FIPS 46-3)
; =========================================================

IP_Table BYTE 58, 50, 42, 34, 26, 18, 10,  2
         BYTE 60, 52, 44, 36, 28, 20, 12,  4
         BYTE 62, 54, 46, 38, 30, 22, 14,  6
         BYTE 64, 56, 48, 40, 32, 24, 16,  8
         BYTE 57, 49, 41, 33, 25, 17,  9,  1
         BYTE 59, 51, 43, 35, 27, 19, 11,  3
         BYTE 61, 53, 45, 37, 29, 21, 13,  5
         BYTE 63, 55, 47, 39, 31, 23, 15,  7

FP_Table BYTE 40,  8, 48, 16, 56, 24, 64, 32
         BYTE 39,  7, 47, 15, 55, 23, 63, 31
         BYTE 38,  6, 46, 14, 54, 22, 62, 30
         BYTE 37,  5, 45, 13, 53, 21, 61, 29
         BYTE 36,  4, 44, 12, 52, 20, 60, 28
         BYTE 35,  3, 43, 11, 51, 19, 59, 27
         BYTE 34,  2, 42, 10, 50, 18, 58, 26
         BYTE 33,  1, 41,  9, 49, 17, 57, 25

E_Table  BYTE 32,  1,  2,  3,  4,  5
         BYTE  4,  5,  6,  7,  8,  9
         BYTE  8,  9, 10, 11, 12, 13
         BYTE 12, 13, 14, 15, 16, 17
         BYTE 16, 17, 18, 19, 20, 21
         BYTE 20, 21, 22, 23, 24, 25
         BYTE 24, 25, 26, 27, 28, 29
         BYTE 28, 29, 30, 31, 32,  1

P_Table  BYTE 16,  7, 20, 21, 29, 12, 28, 17
         BYTE  1, 15, 23, 26,  5, 18, 31, 10
         BYTE  2,  8, 24, 14, 32, 27,  3,  9
         BYTE 19, 13, 30,  6, 22, 11,  4, 25

S_Boxes  BYTE 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7
         BYTE  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8
         BYTE  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0
         BYTE 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13

         BYTE 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10
         BYTE  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5
         BYTE  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15
         BYTE 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9

         BYTE 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8
         BYTE 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1
         BYTE 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7
         BYTE  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12

         BYTE  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15
         BYTE 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9
         BYTE 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4
         BYTE  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14

         BYTE  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9
         BYTE 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6
         BYTE  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14
         BYTE 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3

         BYTE 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11
         BYTE 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8
         BYTE  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6
         BYTE  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13

         BYTE  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1
         BYTE 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6
         BYTE  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2
         BYTE  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12

         BYTE 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7
         BYTE  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2
         BYTE  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8
         BYTE  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11

; GenerateKeySchedule is declared by ModuleB.inc

.code

; =========================================================
; MAIN PROCEDURE
; =========================================================
main PROC
    mov  edx, OFFSET msgTitle
    call WriteString

    ; 1. Plaintext & Key
    mov  edx, OFFSET msgPlain
    call WriteString
    push 8
    push OFFSET testPlaintext
    call PrintHexBlock

    mov  edx, OFFSET msgKey
    call WriteString
    push 8
    push OFFSET testKey
    call PrintHexBlock

    ; 2. Generate Subkeys (Module B)
    push OFFSET SubKeys
    push OFFSET testKey
    call GenerateKeySchedule

    ; 3. Encrypt
    push 0                      ; Mode 0 = Encrypt
    push OFFSET SubKeys
    push OFFSET cipherBuffer
    push OFFSET testPlaintext
    call DES_ProcessBlock

    mov  edx, OFFSET msgEncrypted
    call WriteString
    push 8
    push OFFSET cipherBuffer
    call PrintHexBlock

    ; 4. Decrypt
    push 1                      ; Mode 1 = Decrypt
    push OFFSET SubKeys
    push OFFSET decryptedBuffer
    push OFFSET cipherBuffer
    call DES_ProcessBlock

    mov  edx, OFFSET msgDecrypted
    call WriteString
    push 8
    push OFFSET decryptedBuffer
    call PrintHexBlock

    ; 5. Verify Result
    mov  esi, OFFSET cipherBuffer
    mov  edi, OFFSET expectedCipher
    mov  ecx, 8
VerifyLoop:
    mov  al, BYTE PTR [esi]
    mov  bl, BYTE PTR [edi]
    cmp  al, bl
    jne  VerifyFailed
    inc  esi
    inc  edi
    loop VerifyLoop

    mov  edx, OFFSET msgPass
    call WriteString
    jmp  MainExit

VerifyFailed:
    mov  edx, OFFSET msgFail
    call WriteString

MainExit:
    exit
main ENDP

; =========================================================
; HELPER: PrintHexBlock
; =========================================================
PrintHexBlock PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi

    mov  esi, [ebp + 8]
    mov  ecx, [ebp + 12]
    xor  ebx, ebx

PrintLoop:
    cmp  ebx, ecx
    jge  PrintDone

    movzx eax, BYTE PTR [esi + ebx]
    
    push eax
    shr  al, 4
    cmp  al, 9
    jbe  UpperDigit
    add  al, 'A' - 10
    jmp  PrintUpper
UpperDigit:
    add  al, '0'
PrintUpper:
    call WriteChar

    pop  eax
    and  al, 0Fh
    cmp  al, 9
    jbe  LowerDigit
    add  al, 'A' - 10
    jmp  PrintLower
LowerDigit:
    add  al, '0'
PrintLower:
    call WriteChar

    mov  al, ' '
    call WriteChar

    inc  ebx
    jmp  PrintLoop

PrintDone:
    call Crlf
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
PrintHexBlock ENDP


; =========================================================
; HELPER: ExtractBit
; =========================================================
ExtractBit PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi

    mov  esi, [ebp + 8]
    mov  eax, [ebp + 12]
    dec  eax                   ; 0-indexed

    mov  ebx, eax
    shr  ebx, 3                 ; Byte Index

    and  eax, 7                 ; Bit Offset
    mov  edx, 7
    sub  edx, eax               ; Big-endian MSB bit offset
    mov  cl, dl

    movzx eax, BYTE PTR [esi + ebx]
    shr  eax, cl
    and  eax, 1

    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
ExtractBit ENDP


; =========================================================
; HELPER: SetBit
; =========================================================
SetBit PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi

    mov  esi, [ebp + 8]
    mov  eax, [ebp + 12]
    dec  eax                   ; 0-indexed

    mov  ebx, eax
    shr  ebx, 3                 ; Byte Index

    and  eax, 7
    mov  edx, 7
    sub  edx, eax
    mov  cl, dl

    mov  eax, [ebp + 16]
    cmp  eax, 0
    je   ClearTargetBit

    mov  al, 1
    shl  al, cl
    or   BYTE PTR [esi + ebx], al
    jmp  SetBitDone

ClearTargetBit:
    mov  al, 1
    shl  al, cl
    not  al
    and  BYTE PTR [esi + ebx], al

SetBitDone:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  12
SetBit ENDP


; =========================================================
; CORE: PermuteData
; =========================================================
PermuteData PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]         ; Input
    mov  edi, [ebp + 12]        ; Output
    mov  ebx, [ebp + 16]        ; Table
    mov  ecx, [ebp + 20]        ; Total bits

    mov  eax, ecx
    add  eax, 7
    shr  eax, 3                 ; numBytes
    push ecx
    mov  ecx, eax
    push edi
ClearOutLoop:
    mov  BYTE PTR [edi], 0
    inc  edi
    loop ClearOutLoop
    pop  edi
    pop  ecx

    xor  edx, edx

PermLoop:
    cmp  edx, ecx
    jge  PermDone

    movzx eax, BYTE PTR [ebx + edx]

    push eax
    push esi
    call ExtractBit

    mov  ebx, edx
    inc  ebx
    push eax                    ; Bit val
    push ebx                    ; Bit pos
    push edi
    call SetBit

    mov  ebx, [ebp + 16]        ; Restore Table ptr
    inc  edx
    jmp  PermLoop

PermDone:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  16
PermuteData ENDP


; =========================================================
; CORE: DES_FeistelFunction f(R, K)
; =========================================================
DES_FeistelFunction PROC pR_In:DWORD, pSubKey_In:DWORD, pOutput_Out:DWORD
    LOCAL expandedR[6]:BYTE
    LOCAL xorBuffer[6]:BYTE
    LOCAL sboxOut[4]:BYTE

    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; 1. Expansion (E)
    push 48
    push OFFSET E_Table
    lea  eax, expandedR
    push eax
    push pR_In
    call PermuteData

    ; 2. Subkey XOR
    mov  esi, pSubKey_In
    lea  edi, expandedR
    lea  ebx, xorBuffer
    xor  ecx, ecx

XorSubkeyLoop:
    cmp  ecx, 6
    jge  XorSubkeyDone
    mov  al, BYTE PTR [edi + ecx]
    mov  dl, BYTE PTR [esi + ecx]
    xor  al, dl
    mov  BYTE PTR [ebx + ecx], al
    inc  ecx
    jmp  XorSubkeyLoop
XorSubkeyDone:

    ; 3. S-Box Lookups
    mov  DWORD PTR sboxOut, 0
    xor  ecx, ecx               ; S-Box index (0-7)

SBoxLoop:
    cmp  ecx, 8
    jge  SBoxDone

    ; Bit 1 -> Row bit 1
    mov  eax, ecx
    imul eax, 6
    inc  eax

    push eax
    lea  edx, xorBuffer
    push edx
    call ExtractBit
    mov  ebx, eax
    shl  ebx, 1

    ; Bit 6 -> Row bit 0
    mov  eax, ecx
    imul eax, 6
    add  eax, 6
    push eax
    lea  edx, xorBuffer
    push edx
    call ExtractBit
    or   ebx, eax               ; ebx = Row (0-3)

    ; Bits 2-5 -> Column
    xor  edi, edi
    mov  edx, 1

ColLoop:
    cmp  edx, 4
    jg   ColDone
    
    mov  eax, ecx
    imul eax, 6
    add  eax, edx
    inc  eax                    ; bit position
    push eax
    lea  eax, xorBuffer
    push eax
    call ExtractBit

    shl  edi, 1
    or   edi, eax

    inc  edx
    jmp  ColLoop
ColDone:

    ; Offset S-Box = (i * 64) + (Row * 16) + Column
    mov  eax, ecx
    shl  eax, 6
    mov  edx, ebx
    shl  edx, 4
    add  eax, edx
    add  eax, edi

    movzx eax, BYTE PTR S_Boxes[eax]

    ;  4  sboxOut Buffer
    push ecx                    ;  ECX 
    mov  edx, 0

Write4BitsLoop:
    cmp  edx, 4
    jge  Write4BitsDone

    mov  ebx, eax
    mov  cl, 3
    sub  cl, dl
    shr  ebx, cl
    and  ebx, 1

    mov  esi, [esp]             ;  ecx (S-Box Index)  stack
    imul esi, 4
    add  esi, edx
    inc  esi

    push ebx
    push esi
    lea  ebx, sboxOut
    push ebx
    call SetBit

    inc  edx
    jmp  Write4BitsLoop

Write4BitsDone:
    pop  ecx                    ;  ECX  SBoxLoop 
    inc  ecx
    jmp  SBoxLoop

SBoxDone:

    ; 4. Permutation (P)
    push 32
    push OFFSET P_Table
    push pOutput_Out
    lea  eax, sboxOut
    push eax
    call PermuteData

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret  12
DES_FeistelFunction ENDP


; =========================================================
; CORE: DES_ProcessBlock (Single 64-bit Block)
; =========================================================
DES_ProcessBlock PROC pInputBlock:DWORD, pOutputBlock:DWORD, pSubKeys:DWORD, mode:DWORD
    LOCAL ipBlock[8]:BYTE
    LOCAL L_Val[4]:BYTE
    LOCAL R_Val[4]:BYTE
    LOCAL nextR[4]:BYTE
    LOCAL fOut[4]:BYTE
    LOCAL preOutput[8]:BYTE

    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; 1. Initial Permutation (IP)
    push 64
    push OFFSET IP_Table
    lea  eax, ipBlock
    push eax
    push pInputBlock
    call PermuteData

    lea  esi, ipBlock
    lea  edi, L_Val
    mov  eax, DWORD PTR [esi]
    mov  DWORD PTR [edi], eax

    lea  edi, R_Val
    mov  eax, DWORD PTR [esi + 4]
    mov  DWORD PTR [edi], eax

    ; 2. 16-Round Feistel Loop
    mov  eax, mode
    cmp  eax, 1
    je   SetupDecrypt

    mov  ebx, 0
    jmp  FeistelLoop

SetupDecrypt:
    mov  ebx, 15

FeistelLoop:
    mov  eax, mode
    cmp  eax, 1
    je   CheckDecryptExit

    cmp  ebx, 16
    jge  FeistelDone
    jmp  ProcessRound

CheckDecryptExit:
    cmp  ebx, 0
    jl   FeistelDone

ProcessRound:
    lea  esi, R_Val
    lea  edi, nextR
    mov  eax, DWORD PTR [esi]
    mov  DWORD PTR [edi], eax

    mov  esi, pSubKeys
    mov  eax, ebx
    imul eax, 6
    add  esi, eax

    lea  eax, fOut
    push eax
    push esi
    lea  eax, R_Val
    push eax
    call DES_FeistelFunction

    lea  esi, L_Val
    lea  edi, fOut
    lea  edx, R_Val
    xor  ecx, ecx
XorRLoop:
    cmp  ecx, 4
    jge  XorRDone
    mov  al, BYTE PTR [esi + ecx]
    mov  ah, BYTE PTR [edi + ecx]
    xor  al, ah
    mov  BYTE PTR [edx + ecx], al
    inc  ecx
    jmp  XorRLoop
XorRDone:

    lea  esi, nextR
    lea  edi, L_Val
    mov  eax, DWORD PTR [esi]
    mov  DWORD PTR [edi], eax

    mov  eax, mode
    cmp  eax, 1
    je   DecrRound
    inc  ebx
    jmp  FeistelLoop
DecrRound:
    dec  ebx
    jmp  FeistelLoop

FeistelDone:

    ; 3. 32-bit Swap (R16 + L16)
    lea  esi, R_Val
    lea  edi, preOutput
    mov  eax, DWORD PTR [esi]
    mov  DWORD PTR [edi], eax

    lea  esi, L_Val
    mov  eax, DWORD PTR [esi]
    mov  DWORD PTR [edi + 4], eax

    ; 4. Inverse Initial Permutation (FP / IP^-1)
    push 64
    push OFFSET FP_Table
    push pOutputBlock
    lea  eax, preOutput
    push eax
    call PermuteData

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret  16
DES_ProcessBlock ENDP

END main