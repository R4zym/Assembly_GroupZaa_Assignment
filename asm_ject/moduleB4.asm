TITLE DES Module B - Key Schedule Generator (FIPS 46-3 Fully Compliant)

.386
.model flat, stdcall
.stack 4096
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data

; =========================================================
; INPUT / OUTPUT BUFFERS
; =========================================================
promptKey       BYTE "DES-KEYGEN> Enter 64-bit DES Key (Hex, e.g. 133457799BBCDFF1): ", 0
msgOK           BYTE 0Dh, 0Ah, "[+] Key accepted. Generating 16-round Subkeys...", 0Dh, 0Ah, 0
msgErr          BYTE 0Dh, 0Ah, "[-] Error: Invalid DES key! Must be exactly 16 hexadecimal digits.", 0Dh, 0Ah, 0
msgParityWarn   BYTE "[-] Warning: Key violates FIPS 46-3 Odd Parity rule!", 0Dh, 0Ah, 0
msgWeakKeyWarn  BYTE "[-] Warning: Weak or Semi-Weak DES key detected!", 0Dh, 0Ah, 0
msgC0D0         BYTE "Initial C0 = 0x", 0
msgD0           BYTE ", D0 = 0x", 0
msgRoundPrefix  BYTE "K", 0
msgColon        BYTE ": 0x", 0

keyInput        BYTE 64 DUP(0)
Key64           BYTE 8 DUP(0)

; 16 rounds x 6 bytes (48 bits each) = 96 bytes
SubKeys         BYTE 96 DUP(0)

; Working & Preservation variables
C_Val           DWORD ?
D_Val           DWORD ?
C0_Init         DWORD ?
D0_Init         DWORD ?

; =========================================================
; DES PERMUTED CHOICE 1 (PC-1) - 56 bits
; =========================================================
PC1 BYTE 57,49,41,33,25,17, 9, 1
    BYTE 58,50,42,34,26,18,10, 2
    BYTE 59,51,43,35,27,19,11, 3
    BYTE 60,52,44,36,63,55,47,39
    BYTE 31,23,15, 7,62,54,46,38
    BYTE 30,22,14, 6,61,53,45,37
    BYTE 29,21,13, 5,28,20,12, 4

; =========================================================
; DES LEFT SHIFT SCHEDULE (16 rounds)
; =========================================================
ShiftSchedule BYTE 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1

; =========================================================
; DES PERMUTED CHOICE 2 (PC-2) - 48 bits
; =========================================================
PC2 BYTE 14,17,11,24, 1, 5
    BYTE  3,28,15, 6,21,10
    BYTE 23,19,12, 4,26, 8
    BYTE 16, 7,27,20,13, 2
    BYTE 41,52,31,37,47,55
    BYTE 30,40,51,45,33,48
    BYTE 44,49,39,56,34,53
    BYTE 46,42,50,36,29,32

.code

; =========================================================================
; MAIN PROCEDURE
; =========================================================================
main PROC
    push ebp
    mov  ebp, esp

    ; 1. รับค่า Key จาก Console
    mov  edx, OFFSET promptKey
    call WriteString

    mov  edx, OFFSET keyInput
    mov  ecx, SIZEOF keyInput - 1
    call ReadString

    ; 2. แปลง Hex string เป็น 8-byte Binary
    push OFFSET Key64
    push OFFSET keyInput
    call ParseAndConvertHex
    cmp  eax, 1
    jne  InvalidKey

    ; 3. ตรวจสอบ Parity ตามมาตรฐาน FIPS 46-3
    push OFFSET Key64
    call ValidateKeyParity
    cmp  eax, 1
    je   ParityValid
    mov  edx, OFFSET msgParityWarn
    call WriteString

ParityValid:
    mov  edx, OFFSET msgOK
    call WriteString

    ; 4. คำนวณ Key Schedule 16 รอบ
    push OFFSET SubKeys
    push OFFSET Key64
    call GenerateKeySchedule

    ; 5. แสดงผล C0, D0 และ Subkeys K1 - K16
    push OFFSET SubKeys
    call DisplayAllSubKeys

    jmp  ProgramExit

InvalidKey:
    mov  edx, OFFSET msgErr
    call WriteString

ProgramExit:
    mov  esp, ebp
    pop  ebp
    exit
main ENDP


; =========================================================================
; GenerateKeySchedule
; Parameters:
;   [ebp + 8]  = Pointer ไปยัง 64-bit Key (8 bytes)
;   [ebp + 12] = Pointer ไปยัง Subkeys Buffer (96 bytes)
; Returns: EAX = 1 (Success)
; =========================================================================
GenerateKeySchedule PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]        ; pKey64
    mov  edi, [ebp + 12]       ; pSubKeysOut

    ; ขั้นตอนที่ 1: ทำ PC-1 เพื่อสร้าง C0 และ D0
    push esi
    call GenerateC0D0

    ; สำรองค่า C0, D0 เริ่มต้นไว้สำหรับการแสดงผลหรือ Verification
    mov  eax, C_Val
    mov  C0_Init, eax
    mov  eax, D_Val
    mov  D0_Init, eax

    ; ขั้นตอนที่ 2: วนลูป 16 รอบเพื่อสร้าง Ki
    xor  ebx, ebx              ; ebx = Round index (0 ถึง 15)

RoundLoop:
    cmp  ebx, 16
    jge  KeyGenFinished

    movzx ecx, BYTE PTR ShiftSchedule[ebx]

    ; Circular Rotate Left C_Val
    mov  eax, C_Val
    push ecx
    push eax
    call Rotate28
    mov  C_Val, eax

    ; Circular Rotate Left D_Val
    mov  eax, D_Val
    push ecx
    push eax
    call Rotate28
    mov  D_Val, eax

    ; หาตำแหน่ง Buffer: pSubKeysOut + (round * 6)
    mov  eax, ebx
    imul eax, 6
    lea  edx, [edi + eax]

    ; ทำ PC-2 สร้าง 48-bit Subkey ลงในรอบปัจจุบัน
    push edx
    call GenerateSubKeyPC2

    inc  ebx
    jmp  RoundLoop

KeyGenFinished:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  eax, 1
    mov  esp, ebp
    pop  ebp
    ret  8
GenerateKeySchedule ENDP


; =========================================================================
; GenerateC0D0
; ดำเนินการ Permuted Choice 1 (PC-1)
; Parameters: [ebp + 8] = Pointer to 8-byte Key
; =========================================================================
GenerateC0D0 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]
    xor  edi, edi              ; C accumulator (28-bit)
    xor  ebx, ebx              ; D accumulator (28-bit)
    xor  edx, edx              ; Index (0 ถึง 55)

PC1_Loop:
    cmp  edx, 56
    jge  PC1_Done

    movzx ecx, BYTE PTR PC1[edx]

    push ecx
    push esi
    call GetBit64

    cmp  edx, 28
    jge  PutIntoD

    shl  edi, 1
    or   edi, eax
    jmp  PC1_Next

PutIntoD:
    shl  ebx, 1
    or   ebx, eax

PC1_Next:
    inc  edx
    jmp  PC1_Loop

PC1_Done:
    mov  C_Val, edi
    mov  D_Val, ebx

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4
GenerateC0D0 ENDP


; =========================================================================
; Rotate28 (28-bit Circular Shift Left)
; Parameters:
;   [ebp + 8]  = ค่า 28-bit
;   [ebp + 12] = จำนวนบิตที่จะหมุน (1 หรือ 2)
; =========================================================================
Rotate28 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx

    mov  eax, [ebp + 8]
    and  eax, 0FFFFFFFh
    mov  ecx, [ebp + 12]

RotateLoop:
    cmp  ecx, 0
    jle  RotateDone

    mov  ebx, eax
    shr  ebx, 27
    and  ebx, 1

    shl  eax, 1
    and  eax, 0FFFFFFFh
    or   eax, ebx

    dec  ecx
    jmp  RotateLoop

RotateDone:
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
Rotate28 ENDP


; =========================================================================
; GenerateSubKeyPC2
; ดำเนินการ Permuted Choice 2 (PC-2) 48 bits
; Parameters: [ebp + 8] = Destination Pointer (6 bytes)
; =========================================================================
GenerateSubKeyPC2 PROC
    push ebp
    mov  ebp, esp
    push eax
    push ebx
    push ecx
    push edx
    push edi

    mov  edi, [ebp + 8]
    xor  ebx, ebx              ; Byte accumulator
    xor  ecx, ecx              ; Byte counter (0 ถึง 5)
    xor  edx, edx              ; PC2 table counter (0 ถึง 47)

PC2_Loop:
    cmp  edx, 48
    jge  PC2_Done

    movzx eax, BYTE PTR PC2[edx]
    push eax
    call GetBitCD

    shl  ebx, 1
    or   ebx, eax
    inc  edx

    ; เก็บข้อมูลลง Buffer ทุกๆ 8 บิต
    mov  eax, edx
    and  eax, 7
    cmp  eax, 0
    jne  PC2_Loop

    mov  BYTE PTR [edi + ecx], bl
    inc  ecx
    xor  ebx, ebx
    jmp  PC2_Loop

PC2_Done:
    pop  edi
    pop  edx
    pop  ecx
    pop  ebx
    pop  eax
    mov  esp, ebp
    pop  ebp
    ret  4
GenerateSubKeyPC2 ENDP


; =========================================================================
; GetBitCD
; Parameters: [ebp + 8] = ตำแหน่งบิต (1-56)
; Returns: EAX = ค่าบิต (0 หรือ 1)
; =========================================================================
GetBitCD PROC
    push ebp
    mov  ebp, esp
    push ecx
    push edx

    mov  ecx, [ebp + 8]
    cmp  ecx, 28
    jg   ReadFromD

    mov  eax, C_Val
    mov  edx, 28
    sub  edx, ecx
    mov  cl, dl
    shr  eax, cl
    and  eax, 1
    jmp  BitCD_Exit

ReadFromD:
    mov  eax, D_Val
    sub  ecx, 28
    mov  edx, 28
    sub  edx, ecx
    mov  cl, dl
    shr  eax, cl
    and  eax, 1

BitCD_Exit:
    pop  edx
    pop  ecx
    mov  esp, ebp
    pop  ebp
    ret  4
GetBitCD ENDP


; =========================================================================
; GetBit64
; Parameters:
;   [ebp + 8]  = Pointer to 8-byte Key
;   [ebp + 12] = ตำแหน่งบิตตามมาตรฐาน FIPS (1 ถึง 64)
; Returns: EAX = ค่าบิต (0 หรือ 1)
; =========================================================================
GetBit64 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi

    mov  esi, [ebp + 8]
    mov  eax, [ebp + 12]
    dec  eax                   ; แปลงเป็น 0-indexed (0 ถึง 63)

    mov  ebx, eax
    shr  ebx, 3                ; Byte index (0 ถึง 7)

    and  eax, 7                ; Bit offset ภายในไบต์
    mov  edx, 7
    sub  edx, eax              ; กลับด้านเพื่อให้ MSB คือ Bit 0 ตามหลัก Big-Endian
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
GetBit64 ENDP


; =========================================================================
; ValidateKeyParity (FIPS 46-3 Check)
; ตรวจสอบว่าทั้ง 8 ไบต์ มีจำนวนบิต 1 เป็นเลขคี่หรือไม่
; Parameters: [ebp + 8] = Pointer to 8-byte Key
; Returns: EAX = 1 (Valid Parity), 0 (Invalid Parity)
; =========================================================================
ValidateKeyParity PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push esi

    mov  esi, [ebp + 8]
    xor  ecx, ecx

CheckByteParity:
    cmp  ecx, 8
    jge  ParityPassed

    mov  al, BYTE PTR [esi + ecx]
    test al, al                ; คำนวณ Parity Flag บน AL
    jp   ParityFailed          ; ใน x86: ถ้า PF=1 แสดงว่าเป็น Even Parity (ผิดกฎ FIPS)

    inc  ecx
    jmp  CheckByteParity

ParityPassed:
    mov  eax, 1
    jmp  ParityExit

ParityFailed:
    xor  eax, eax

ParityExit:
    pop  esi
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4
ValidateKeyParity ENDP


; =========================================================================
; ParseAndConvertHex
; Parameters:
;   [ebp + 8]  = Pointer ไปยัง String Input
;   [ebp + 12] = Pointer ไปยัง Buffer รับข้อมูล 8 ไบต์
; Returns: EAX = 1 (สำเร็จ), 0 (รูปแบบผิดพลาด)
; =========================================================================
ParseAndConvertHex PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]
    mov  edi, [ebp + 12]

    ; ข้าม Prefix "0x" หรือ "0X"
    cmp  BYTE PTR [esi], '0'
    jne  StartParsing
    cmp  BYTE PTR [esi + 1], 'x'
    je   SkipPrefix
    cmp  BYTE PTR [esi + 1], 'X'
    jne  StartParsing

SkipPrefix:
    add  esi, 2

StartParsing:
    xor  ecx, ecx
CountLength:
    cmp  BYTE PTR [esi + ecx], 0
    je   CheckLength
    inc  ecx
    jmp  CountLength

CheckLength:
    cmp  ecx, 16
    jne  ParseFailed

    xor  ecx, ecx

ConvertByteLoop:
    cmp  ecx, 8
    jge  ParseSuccess

    ; แปลง Nibble บน
    movzx eax, BYTE PTR [esi]
    push eax
    call HexCharToValue
    cmp  eax, -1
    je   ParseFailed
    shl  eax, 4
    mov  ebx, eax

    ; แปลง Nibble ล่าง
    movzx eax, BYTE PTR [esi + 1]
    push eax
    call HexCharToValue
    cmp  eax, -1
    je   ParseFailed
    or   ebx, eax

    mov  BYTE PTR [edi + ecx], bl
    add  esi, 2
    inc  ecx
    jmp  ConvertByteLoop

ParseSuccess:
    mov  eax, 1
    jmp  ParseReturn

ParseFailed:
    xor  eax, eax

ParseReturn:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
ParseAndConvertHex ENDP


; =========================================================================
; HexCharToValue
; แปลง ASCII Character เป็นตัวเลขฐานสิบหก (0-15)
; =========================================================================
HexCharToValue PROC
    push ebp
    mov  ebp, esp

    mov  eax, [ebp + 8]

    cmp  al, '0'
    jb   CheckUpper
    cmp  al, '9'
    ja   CheckUpper
    sub  al, '0'
    movzx eax, al
    jmp  HexCharDone

CheckUpper:
    cmp  al, 'A'
    jb   CheckLower
    cmp  al, 'F'
    ja   CheckLower
    sub  al, 'A'
    add  al, 10
    movzx eax, al
    jmp  HexCharDone

CheckLower:
    cmp  al, 'a'
    jb   InvalidHexChar
    cmp  al, 'f'
    ja   InvalidHexChar
    sub  al, 'a'
    add  al, 10
    movzx eax, al
    jmp  HexCharDone

InvalidHexChar:
    mov  eax, -1

HexCharDone:
    mov  esp, ebp
    pop  ebp
    ret  4
HexCharToValue ENDP


; =========================================================================
; PrintHexByte (เขียนขึ้นทดแทน WriteHexB ที่ไม่มีใน Irvine32)
; พิมพ์ค่าใน AL ออกหน้าจอเป็นเลขฐาน 16 จำนวน 2 หลักเสมอ
; =========================================================================
PrintHexByte PROC
    push eax
    push ebx

    mov  bl, al                ; สำรองค่าเดิม

    ; พิมพ์ Upper Nibble
    shr  al, 4
    cmp  al, 9
    jbe  DigitUpper
    add  al, 'A' - 10
    jmp  PrintUpper
DigitUpper:
    add  al, '0'
PrintUpper:
    call WriteChar

    ; พิมพ์ Lower Nibble
    mov  al, bl
    and  al, 0Fh
    cmp  al, 9
    jbe  DigitLower
    add  al, 'A' - 10
    jmp  PrintLower
DigitLower:
    add  al, '0'
PrintLower:
    call WriteChar

    pop  ebx
    pop  eax
    ret
PrintHexByte ENDP


; =========================================================================
; DisplayAllSubKeys
; แสดงค่า C0, D0 เริ่มต้น และแสดง Subkeys K1 ถึง K16 ขนาด 48 บิต
; Parameters: [ebp + 8] = Pointer ไปยัง Buffer Subkeys 96 ไบต์
; =========================================================================
DisplayAllSubKeys PROC
    push ebp
    mov  ebp, esp
    pushad

    mov  esi, [ebp + 8]

    ; 1. แสดงค่าเริ่มต้น C0 และ D0 ดั้งเดิม
    call Crlf
    mov  edx, OFFSET msgC0D0
    call WriteString
    mov  eax, C0_Init
    call WriteHex

    mov  edx, OFFSET msgD0
    call WriteString
    mov  eax, D0_Init
    call WriteHex
    call Crlf
    call Crlf

    ; 2. แสดง K1 - K16 (48-bit ในแต่ละรอบ)
    xor  ecx, ecx

DisplayRoundLoop:
    cmp  ecx, 16
    jge  DisplayDone

    mov  edx, OFFSET msgRoundPrefix
    call WriteString
    mov  eax, ecx
    inc  eax
    call WriteDec

    ; จัด Format ย่อหน้า K1 ถึง K9 ให้ตรงกับ K10 ถึง K16
    cmp  eax, 10
    jae  SkipSpacePad
    mov  al, ' '
    call WriteChar

SkipSpacePad:
    mov  edx, OFFSET msgColon
    call WriteString

    ; คำนวณ Pointer ของรอบปัจจุบัน: esi + (round * 6)
    mov  eax, ecx
    imul eax, 6
    lea  ebx, [esi + eax]

    ; พิมพ์ 6 ไบต์ (12 Hex digits)
    xor  edx, edx
PrintBytesLoop:
    cmp  edx, 6
    jge  PrintBytesDone
    mov  al, BYTE PTR [ebx + edx]
    call PrintHexByte
    inc  edx
    jmp  PrintBytesLoop

PrintBytesDone:
    call Crlf
    inc  ecx
    jmp  DisplayRoundLoop

DisplayDone:
    call Crlf
    popad
    mov  esp, ebp
    pop  ebp
    ret  4
DisplayAllSubKeys ENDP

END main