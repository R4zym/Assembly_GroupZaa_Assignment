TITLE DES Module B - Key Schedule Generation

.386
.model flat, stdcall
.stack 4096

PUBLIC GenerateKeySchedule

.data

; PC-1 Table (56 entries: 1..64)
PC1 BYTE 57, 49, 41, 33, 25, 17,  9
    BYTE  1, 58, 50, 42, 34, 26, 18
    BYTE 10,  2, 59, 51, 43, 35, 27
    BYTE 19, 11,  3, 60, 52, 44, 36
    BYTE 63, 55, 47, 39, 31, 23, 15
    BYTE  7, 62, 54, 46, 38, 30, 22
    BYTE 14,  6, 61, 53, 45, 37, 29
    BYTE 21, 13,  5, 28, 20, 12,  4

; Shift Schedule (16 rounds)
ShiftSchedule BYTE 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1

; PC-2 Table (48 entries: 1..56)
PC2 BYTE 14, 17, 11, 24,  1,  5
    BYTE  3, 28, 15,  6, 21, 10
    BYTE 23, 19, 12,  4, 26,  8
    BYTE 16,  7, 27, 20, 13,  2
    BYTE 41, 52, 31, 37, 47, 55
    BYTE 30, 40, 51, 45, 33, 48
    BYTE 44, 49, 39, 56, 34, 53
    BYTE 46, 42, 50, 36, 29, 32

C_Val DWORD 0
D_Val DWORD 0


.code

; =========================================================
; GetBit64 - อ่านบิตที่ bitPos (1..64) จาก pKey (MSB First)
; =========================================================
GetBit64 PROC pKey:PTR BYTE, bitPos:DWORD
    push ebx
    push ecx
    push edx
    push esi

    mov  esi, pKey
    mov  eax, bitPos
    dec  eax                   ; bitPos 1..64 -> 0..63

    mov  ebx, eax
    shr  ebx, 3                ; byteIndex = bitPos / 8
    and  eax, 7                ; bitIndex = bitPos % 8

    movzx edx, BYTE PTR [esi + ebx]
    mov  ecx, 7
    sub  ecx, eax              ; Shift = 7 - bitIndex (MSB First)
    shr  edx, cl
    and  edx, 1
    mov  eax, edx

    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
GetBit64 ENDP


; =========================================================
; GenerateC0D0 - คำนวณ C0 และ D0 จาก PC1
; =========================================================
GenerateC0D0 PROC pKey:PTR BYTE
    push ebx
    push ecx
    push edx
    push esi

    mov  C_Val, 0
    mov  D_Val, 0
    xor  edx, edx              ; index 0..55

PC1_Loop:
    cmp  edx, 56
    jge  PC1_Done

    movzx ecx, BYTE PTR PC1[edx]
    
    INVOKE GetBit64, pKey, ecx ; EAX = bit value (0 or 1)

    cmp  edx, 28
    jge  AddToD

AddToC:
    mov  ebx, C_Val
    shl  ebx, 1
    or   ebx, eax
    mov  C_Val, ebx
    jmp  NextPC1

AddToD:
    mov  ebx, D_Val
    shl  ebx, 1
    or   ebx, eax
    mov  D_Val, ebx

NextPC1:
    inc  edx
    jmp  PC1_Loop

PC1_Done:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
GenerateC0D0 ENDP


; =========================================================
; GetBitCD - อ่านบิตที่ pos (1..56) จาก C_Val หรือ D_Val
; =========================================================
GetBitCD PROC pos:DWORD
    push ecx
    push edx

    mov  eax, pos
    cmp  eax, 28
    jg   FromD

FromC:
    mov  ecx, 28
    sub  ecx, eax
    mov  edx, C_Val
    shr  edx, cl
    and  edx, 1
    mov  eax, edx
    jmp  GetCDDone

FromD:
    sub  eax, 28
    mov  ecx, 28
    sub  ecx, eax
    mov  edx, D_Val
    shr  edx, cl
    and  edx, 1
    mov  eax, edx

GetCDDone:
    pop  edx
    pop  ecx
    ret
GetBitCD ENDP


; =========================================================
; Rotate28 - เลื่อนบิตทางซ้ายแบบวนรอบสำหรับ 28 บิต
; =========================================================
Rotate28 PROC val:DWORD, shiftCnt:DWORD
    push ecx
    push edx

    mov  eax, val
    mov  ecx, shiftCnt

Rot28_Loop:
    cmp  ecx, 0
    je   Rot28_Done

    shl  eax, 1
    test eax, 10000000h        ; เช็กบิตที่ 28
    jz   NoWrap28
    or   eax, 1                ; วนบิตกลับมาบิต 0
NoWrap28:
    and  eax, 0FFFFFFFh        ; Mask เหลือ 28 บิต

    dec  ecx
    jmp  Rot28_Loop

Rot28_Done:
    pop  edx
    pop  ecx
    ret
Rotate28 ENDP


; =========================================================
; GenerateSubKeyPC2 - สร้าง Subkey 6 ไบต์ (48 บิต) ผ่าน PC2
; =========================================================
GenerateSubKeyPC2 PROC pOutBuffer:PTR BYTE
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  edi, pOutBuffer
    xor  edx, edx              ; bit counter 0..47
    xor  ebx, ebx              ; accumulator byte
    xor  esi, esi              ; byte index 0..5

PC2_Loop:
    cmp  edx, 48
    jge  PC2_Done

    movzx eax, BYTE PTR PC2[edx]
    
    INVOKE GetBitCD, eax       ; EAX = bit value

    shl  ebx, 1
    or   ebx, eax

    inc  edx

    mov  eax, edx
    and  eax, 7
    cmp  eax, 0
    jne  PC2_Loop

    mov  BYTE PTR [edi + esi], bl
    inc  esi
    xor  ebx, ebx
    jmp  PC2_Loop

PC2_Done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
GenerateSubKeyPC2 ENDP


; =========================================================
; GenerateKeySchedule - ฟังก์ชันหลัก (แก้ไขการจัด Stack แล้ว)
; =========================================================
GenerateKeySchedule PROC pKey:PTR BYTE, pSubKeys:PTR BYTE
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, pKey
    mov  edi, pSubKeys

    test esi, esi
    jz   KeyScheduleFail
    test edi, edi
    jz   KeyScheduleFail

    ; Step 1: PC-1
    INVOKE GenerateC0D0, esi

    ; Step 2: Loop 16 Rounds
    xor  ebx, ebx              ; EBX = round 0..15

KeyScheduleLoop:
    cmp  ebx, 16
    jge  KeyScheduleDone

    ; Get shift count
    movzx ecx, BYTE PTR ShiftSchedule[ebx]

    ; Rotate C
    INVOKE Rotate28, C_Val, ecx
    mov  C_Val, eax

    ; Rotate D
    INVOKE Rotate28, D_Val, ecx
    mov  D_Val, eax

    ; Calculate output buffer pointer: pSubKeys + (round * 6)
    mov  eax, ebx
    imul eax, 6
    lea  edx, [edi + eax]

    ; Generate Subkey via PC-2
    INVOKE GenerateSubKeyPC2, edx

    inc  ebx
    jmp  KeyScheduleLoop

KeyScheduleDone:
    mov  eax, 1
    jmp  KeyScheduleExit

KeyScheduleFail:
    xor  eax, eax

KeyScheduleExit:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
GenerateKeySchedule ENDP

END