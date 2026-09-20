TITLE DES Module B - Key Schedule Generator (Complete Standalone & Test)

INCLUDE Irvine32.inc
INCLUDE C:\Irvine\Irvine32.inc
.386
.model flat, stdcall
.stack 4096

.data

; =========================================================
; INPUT / OUTPUT BUFFERS
; =========================================================
promptKey       BYTE "DES-KEYGEN> Enter 64-bit DES Key (e.g. 133457799BBCDFF1 or 0x133457799BBCDFF1): ", 0
msgOK           BYTE 0Dh, 0Ah, "[+] Key accepted. Generating 16-round Subkeys...", 0Dh, 0Ah, 0
msgErr          BYTE 0Dh, 0Ah, "[-] Error: Invalid DES key! Must be 16 hexadecimal digits.", 0Dh, 0Ah, 0
msgC0D0         BYTE "Initial C0 = 0x", 0
msgD0           BYTE ", D0 = 0x", 0
msgRoundPrefix  BYTE "K", 0
msgColon        BYTE ": 0x", 0

keyInput        BYTE 64 DUP(0)
Key64           BYTE 8 DUP(0)

; 16 rounds x 6 bytes (48 bits each) = 96 bytes
SubKeys         BYTE 96 DUP(0)

; Working variables (28-bit each)
C_Val           DWORD ?
D_Val           DWORD ?


; =========================================================
; DES PERMUTED CHOICE 1 (PC-1) - 56 bits
; =========================================================
PC1 BYTE 57,49,41,33,25,17,9, 1
    BYTE 58,50,42,34,26,18,10,2
    BYTE 59,51,43,35,27,19,11,3
    BYTE 60,52,44,36,63,55,47,39
    BYTE 31,23,15,7, 62,54,46,38
    BYTE 30,22,14,6, 61,53,45,37
    BYTE 29,21,13,5, 28,20,12,4


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
; MAIN PROCEDURE (Interactive Test Mode)
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

    ; 3. คำนวณ Key Schedule 16 รอบ
    mov  edx, OFFSET msgOK
    call WriteString

    push OFFSET SubKeys
    push OFFSET Key64
    call GenerateKeySchedule

    ; 4. แสดงผลผลลัพธ์ C0, D0 และ Subkeys K1 - K16
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
; รับ:
;   [ebp + 8]  = Pointer ไปยัง 64-bit Key (8 bytes)
;   [ebp + 12] = Pointer ไปยัง Buffer ปลายทางของ Subkeys (96 bytes)
; คืนค่า:
;   EAX = 1 (Success)
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

    ; -----------------------------------------------------
    ; ขั้นตอนที่ 1: ทำ PC-1 เพื่อสร้าง C0 และ D0 (อย่างละ 28-bit)
    ; -----------------------------------------------------
    push esi
    call GenerateC0D0

    ; -----------------------------------------------------
    ; ขั้นตอนที่ 2: วนลูป 16 รอบ เพื่อคำนวณ Ki
    ; -----------------------------------------------------
    xor  ebx, ebx              ; ebx = round index (0 ถึง 15)

RoundLoop:
    cmp  ebx, 16
    jge  KeyGenFinished

    ; ดึงจำนวนบิตที่จะ Shift ประจำรอบนี้ (1 หรือ 2)
    movzx ecx, BYTE PTR ShiftSchedule[ebx]

    ; หมุนบิตทางซ้ายของ C_Val (28-bit circular rotate)
    mov  eax, C_Val
    push ecx
    push eax
    call Rotate28
    mov  C_Val, eax

    ; หมุนบิตทางซ้ายของ D_Val (28-bit circular rotate)
    mov  eax, D_Val
    push ecx
    push eax
    call Rotate28
    mov  D_Val, eax

    ; หาตำแหน่งบันทึก SubKey รอบปัจจุบัน: pSubKeysOut + (round * 6)
    mov  eax, ebx
    imul eax, 6
    lea  edx, [edi + eax]      ; edx = destination pointer สำหรับ 6 ไบต์นี้

    ; ทำ PC-2 เพื่อรวม C_Val และ D_Val ออกมาเป็น 48-bit Subkey
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
    mov  eax, 1                ; Return 1 (Success)
    mov  esp, ebp
    pop  ebp
    ret  8
GenerateKeySchedule ENDP


; =========================================================================
; GenerateC0D0
; ดำเนินการ Permuted Choice 1 (PC-1)
; พารามิเตอร์: [ebp + 8] = Pointer ไปยัง 8-byte Key
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
    xor  edx, edx              ; Index ของ PC1 (0 ถึง 55)

PC1_Loop:
    cmp  edx, 56
    jge  PC1_Done

    movzx ecx, BYTE PTR PC1[edx] ; ตำแหน่งบิตตามมาตรฐาน (1-64)

    ; ดึงบิตที่ ecx จากคีย์ 64 บิต
    push ecx
    push esi
    call GetBit64

    ; บิตที่ 0-27 ลง C_Val, บิตที่ 28-55 ลง D_Val
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
; Rotate28
; พารามิเตอร์:
;   [ebp + 8]  = ค่า 28-bit
;   [ebp + 12] = จำนวนบิตที่จะหมุน (1 หรือ 2)
; คืนค่า: EAX = ค่าที่หมุนแล้ว
; =========================================================================
Rotate28 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx

    mov  eax, [ebp + 8]
    and  eax, 0FFFFFFFh        ; ป้องกันบิตส่วนเกิน
    mov  ecx, [ebp + 12]

RotateLoop:
    cmp  ecx, 0
    jle  RotateDone

    ; ดึง MSB บิตที่ 27 เพื่อนำไปวนเข้าบิต 0
    mov  ebx, eax
    shr  ebx, 27
    and  ebx, 1

    shl  eax, 1
    and  eax, 0FFFFFFFh
    or   eax, ebx

    dec  ecx
    jmp  RotateLoop

RotateDone:
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
Rotate28 ENDP


; =========================================================================
; GenerateSubKeyPC2
; ดำเนินการ Permuted Choice 2 (PC-2) 48 bits
; พารามิเตอร์: [ebp + 8] = Destination Pointer (6 ไบต์)
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
    xor  ebx, ebx              ; ไบต์สะสม
    xor  ecx, ecx              ; ตัวนับไบต์ปลายทาง (0 ถึง 5)
    xor  edx, edx              ; ตัวนับตาราง PC-2 (0 ถึง 47)

PC2_Loop:
    cmp  edx, 48
    jge  PC2_Done

    movzx eax, BYTE PTR PC2[edx] ; ตำแหน่งบิต (1-56)

    push eax
    call GetBitCD              ; คืนค่าบิต (0 หรือ 1) ใน EAX

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
; พารามิเตอร์: [ebp + 8] = ตำแหน่งบิต 1-56 (1-28 มาจาก C, 29-56 มาจาก D)
; คืนค่า: EAX = บิต 0 หรือ 1
; =========================================================================
GetBitCD PROC
    push ebp
    mov  ebp, esp
    push ecx
    push edx

    mov  ecx, [ebp + 8]
    cmp  ecx, 28
    jg   ReadFromD

    ; อ่านจาก C_Val (1-28)
    mov  eax, C_Val
    mov  edx, 28
    sub  edx, ecx
    mov  cl, dl
    shr  eax, cl
    and  eax, 1
    jmp  BitCD_Exit

ReadFromD:
    ; อ่านจาก D_Val (29-56)
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
; พารามิเตอร์:
;   [ebp + 8]  = Pointer ไปยัง 8-byte Key
;   [ebp + 12] = ตำแหน่งบิตตามมาตรฐาน 1-64 (1 คือบิตซ้ายสุดของไบต์แรก)
; คืนค่า: EAX = 0 หรือ 1
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
    shr  ebx, 3                ; ebx = byte index (eax / 8)

    and  eax, 7                ; eax = bit index ภายในไบต์ (0 ถึง 7)
    mov  edx, 7
    sub  edx, eax              ; edx = 7 - bit_index (เพื่อให้ MSB เป็นบิตแรก)
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
; ParseAndConvertHex
; รองรับทั้งแบบธรรมดา "133457799BBCDFF1" และแบบมี prefix "0x"
; พารามิเตอร์:
;   [ebp + 8]  = Pointer ไปยัง String Input
;   [ebp + 12] = Pointer ไปยัง 8-byte Array ปลายทาง
; คืนค่า: EAX = 1 (Valid), 0 (Invalid)
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

    ; ตรวจสอบและข้าม prefix "0x" หรือ "0X" (ถ้ามี)
    cmp  BYTE PTR [esi], '0'
    jne  StartParsing
    cmp  BYTE PTR [esi + 1], 'x'
    je   SkipPrefix
    cmp  BYTE PTR [esi + 1], 'X'
    jne  StartParsing

SkipPrefix:
    add  esi, 2

StartParsing:
    ; ตรวจสอบความยาวตัวอักษร Hex ว่ามีครบ 16 ตัวพอดีหรือไม่
    xor  ecx, ecx
CountLength:
    cmp  BYTE PTR [esi + ecx], 0
    je   CheckLength
    inc  ecx
    jmp  CountLength

CheckLength:
    cmp  ecx, 16
    jne  ParseFailed

    ; แปลงทีละคู่ (16 ตัวอักษร -> 8 ไบต์)
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

    ; เก็บไบต์ลง Buffer
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
; แปลงอักขระ ASCII 1 ตัว เป็นค่า 0-15
; พารามิเตอร์: [ebp + 8] = ASCII character code
; คืนค่า: EAX = 0-15 (ถ้าเป็น Hex ถูกต้อง) หรือ -1 (ถ้าไม่ใช่)
; =========================================================================
HexCharToValue PROC
    push ebp
    mov  ebp, esp
    push ebx

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
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4
HexCharToValue ENDP


; =========================================================================
; DisplayAllSubKeys
; แสดงผลค่า C0, D0 และ Subkeys K1 ถึง K16
; พารามิเตอร์: [ebp + 8] = Pointer ไปยัง Subkeys 96 ไบต์
; =========================================================================
DisplayAllSubKeys PROC
    push ebp
    mov  ebp, esp
    pushad

    mov  esi, [ebp + 8]

    ; 1. แสดง C0 และ D0
    call Crlf
    mov  edx, OFFSET msgC0D0
    call WriteString
    mov  eax, C_Val
    call WriteHex

    mov  edx, OFFSET msgD0
    call WriteString
    mov  eax, D_Val
    call WriteHex
    call Crlf
    call Crlf

    ; 2. แสดง K1 - K16 (48-bit แต่ละรอบ)
    xor  ecx, ecx              ; ecx = round index (0 ถึง 15)

DisplayRoundLoop:
    cmp  ecx, 16
    jge  DisplayDone

    ; แสดงป้ายกำกับ K01 - K16
    mov  edx, OFFSET msgRoundPrefix
    call WriteString
    mov  eax, ecx
    inc  eax
    call WriteDec

    mov  edx, OFFSET msgColon
    call WriteString

    ; คำนวณตำแหน่ง 6 ไบต์ของ Subkey รอบนี้
    mov  eax, ecx
    imul eax, 6
    lea  ebx, [esi + eax]      ; ebx = pointer ไปยัง Subkey รอบนี้

    ; พิมพ์ 6 ไบต์ (12 Hex digits)
    xor  edx, edx
PrintBytesLoop:
    cmp  edx, 6
    jge  PrintBytesDone
    movzx eax, BYTE PTR [ebx + edx]
    
    ; จัด Format ให้มี leading zero สำหรับไบต์ที่มีหลักเดียว (< 10h)
    cmp  al, 10h
    jae  PrintDirectByte
    push eax
    mov  al, '0'
    call WriteChar
    pop  eax

PrintDirectByte:
    call WriteHexB
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