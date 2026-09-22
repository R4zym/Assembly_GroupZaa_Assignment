TITLE DES Module A - Shell Core & FSM Command Parser

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

; ประกาศ Prototype ของ Module B
GenerateKeySchedule PROTO :PTR BYTE, :PTR BYTE


.data

; =========================================================
; CONSTANTS
; =========================================================

CMD_UNKNOWN  EQU 0
CMD_KEYGEN   EQU 1
CMD_ENCRYPT  EQU 2
CMD_DECRYPT  EQU 3
CMD_DUMP     EQU 4
CMD_STATS    EQU 5
CMD_CLEAR    EQU 6
CMD_EXIT     EQU 7


; =========================================================
; STRINGS & LABELS
; =========================================================

prompt          BYTE "DES-SHELL> ", 0

msgKeygen       BYTE "[KEYGEN command detected]", 0Dh, 0Ah, 0
msgEncrypt      BYTE "[ENCRYPT command detected]", 0Dh, 0Ah, 0
msgDecrypt      BYTE "[DECRYPT command detected]", 0Dh, 0Ah, 0
msgDump         BYTE "[DUMP command detected]", 0Dh, 0Ah, 0
msgStats        BYTE "[STATS command detected]", 0Dh, 0Ah, 0
msgClear        BYTE "[CLEAR command detected]", 0Dh, 0Ah, 0

msgUnknown      BYTE "ERROR: Unknown command", 0Dh, 0Ah, 0
msgKeyFail      BYTE "ERROR: Invalid Hex Key or Key Generation Failed", 0Dh, 0Ah, 0
msgExit         BYTE "Exiting DES Command-Line Shell...", 0Dh, 0Ah, 0

cmdKEYGEN       BYTE "KEYGEN", 0
cmdENCRYPT      BYTE "ENCRYPT", 0
cmdDECRYPT      BYTE "DECRYPT", 0
cmdDUMP         BYTE "DUMP", 0
cmdSTATS        BYTE "STATS", 0
cmdCLEAR        BYTE "CLEAR", 0
cmdEXIT         BYTE "EXIT", 0

hexDigits       BYTE "0123456789ABCDEF"
newline         BYTE 0Dh, 0Ah, 0

labelK1         BYTE "K1  = ", 0
labelK2         BYTE "K2  = ", 0
labelK3         BYTE "K3  = ", 0
labelK4         BYTE "K4  = ", 0
labelK5         BYTE "K5  = ", 0
labelK6         BYTE "K6  = ", 0
labelK7         BYTE "K7  = ", 0
labelK8         BYTE "K8  = ", 0
labelK9         BYTE "K9  = ", 0
labelK10        BYTE "K10 = ", 0
labelK11        BYTE "K11 = ", 0
labelK12        BYTE "K12 = ", 0
labelK13        BYTE "K13 = ", 0
labelK14        BYTE "K14 = ", 0
labelK15        BYTE "K15 = ", 0
labelK16        BYTE "K16 = ", 0

SubKeyLabels    DWORD OFFSET labelK1,  OFFSET labelK2,  OFFSET labelK3,  OFFSET labelK4
                DWORD OFFSET labelK5,  OFFSET labelK6,  OFFSET labelK7,  OFFSET labelK8
                DWORD OFFSET labelK9,  OFFSET labelK10, OFFSET labelK11, OFFSET labelK12
                DWORD OFFSET labelK13, OFFSET labelK14, OFFSET labelK15, OFFSET labelK16


; =========================================================
; BUFFERS
; =========================================================

inputBuffer     BYTE 256 DUP(0)
desKey          BYTE 8 DUP(0)       ; 64-bit Binary Key
subKeys         BYTE 96 DUP(0)      ; 16 Subkeys x 6 Bytes = 96 Bytes


.code

; =========================================================
; MAIN
; =========================================================

main PROC

MainLoop:

    mov  edx, OFFSET prompt
    call WriteString

    mov  edx, OFFSET inputBuffer
    mov  ecx, SIZEOF inputBuffer - 1
    call ReadString

    cmp  eax, 0
    je   MainLoop

    push OFFSET inputBuffer
    call ParseCommand

    cmp  eax, CMD_KEYGEN
    je   HandleKeygen

    cmp  eax, CMD_ENCRYPT
    je   HandleEncrypt

    cmp  eax, CMD_DECRYPT
    je   HandleDecrypt

    cmp  eax, CMD_DUMP
    je   HandleDump

    cmp  eax, CMD_STATS
    je   HandleStats

    cmp  eax, CMD_CLEAR
    je   HandleClear

    cmp  eax, CMD_EXIT
    je   HandleExit

    mov  edx, OFFSET msgUnknown
    call WriteString
    jmp  MainLoop


; =========================================================
; COMMAND HANDLERS
; =========================================================

HandleKeygen:

    mov  edx, OFFSET msgKeygen
    call WriteString

    ; ข้ามคำว่า "KEYGEN " (7 ตัวอักษร) เพื่ออ่าน Hex String
    mov  esi, OFFSET inputBuffer
    add  esi, 7

SkipSpaceLoop:
    mov  al, [esi]
    cmp  al, ' '
    jne  StartKeyConv
    inc  esi
    jmp  SkipSpaceLoop

StartKeyConv:
    ; แปลง Hex String (16 ตัวอักษร) -> 8-Byte Binary Key
    push OFFSET desKey
    push esi
    call ConvertHexKey
    cmp  eax, 1
    jne  KeygenFail

    ; เรียก Module B สร้าง Subkeys
    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  KeygenFail

    ; พิมพ์ K1 - K16
    call DisplaySubKeys
    jmp  MainLoop

KeygenFail:

    mov  edx, OFFSET msgKeyFail
    call WriteString
    jmp  MainLoop


HandleEncrypt:
    mov  edx, OFFSET msgEncrypt
    call WriteString
    jmp  MainLoop

HandleDecrypt:
    mov  edx, OFFSET msgDecrypt
    call WriteString
    jmp  MainLoop

HandleDump:
    mov  edx, OFFSET msgDump
    call WriteString
    jmp  MainLoop

HandleStats:
    mov  edx, OFFSET msgStats
    call WriteString
    jmp  MainLoop

HandleClear:
    mov  edx, OFFSET msgClear
    call WriteString
    jmp  MainLoop

HandleExit:
    mov  edx, OFFSET msgExit
    call WriteString
    exit

main ENDP


; =========================================================
; DisplaySubKeys - แสดงผล K1 ถึง K16
; =========================================================

DisplaySubKeys PROC
    push ebx
    push ecx
    push edx
    push esi

    xor  ebx, ebx              ; round index (0..15)

PrintLoop:
    cmp  ebx, 16
    jge  PrintDone

    mov  edx, SubKeyLabels[ebx*4]
    call WriteString

    ; คำนวณ offset: subKeys + (round * 6)
    mov  eax, ebx
    imul eax, 6
    mov  esi, OFFSET subKeys
    add  esi, eax

    xor  ecx, ecx
ByteLoop:
    cmp  ecx, 6
    jge  ByteDone

    movzx eax, BYTE PTR [esi + ecx]

    ; High Nibble
    push eax                     ; สำรองค่าไบต์เดิมไว้ใน Stack
    shr  eax, 4
    and  eax, 0Fh
    mov  al, hexDigits[eax]      ; ย้ายตัวอักษร Hex เข้า AL
    call WriteChar               ; พิมพ์ High Nibble

    ; Low Nibble
    pop  eax                     ; ดึงค่าไบต์เดิมกลับมาจาก Stack
    and  eax, 0Fh
    mov  al, hexDigits[eax]      ; ย้ายตัวอักษร Hex เข้า AL
    call WriteChar               ; พิมพ์ Low Nibble

    inc  ecx
    jmp  ByteLoop

ByteDone:
    mov  edx, OFFSET newline
    call WriteString

    inc  ebx
    jmp  PrintLoop

PrintDone:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
DisplaySubKeys ENDP


; =========================================================
; ConvertHexKey - แปลง 16-Hex Chars เป็น 8-Byte Binary Key
; =========================================================

ConvertHexKey PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]        ; Pointer Hex string
    mov  edi, [ebp + 12]       ; Output desKey buffer

    xor  ecx, ecx
ConvLoop:
    cmp  ecx, 8
    jge  ConvDone

    mov  al, [esi]
    call HexCharToNibble
    cmp  al, 0FFh
    je   ConvFail
    shl  al, 4
    mov  bl, al

    inc  esi

    mov  al, [esi]
    call HexCharToNibble
    cmp  al, 0FFh
    je   ConvFail
    or   bl, al

    mov  [edi + ecx], bl
    inc  esi
    inc  ecx
    jmp  ConvLoop

ConvDone:
    mov  eax, 1
    jmp  ConvExit

ConvFail:
    xor  eax, eax

ConvExit:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
ConvertHexKey ENDP


; Fix: เปลี่ยน jbe IsDigit เป็น jbe HexIsDigit
HexCharToNibble PROC
    cmp  al, '0'
    jb   InvalidHex
    cmp  al, '9'
    jbe  HexIsDigit
    cmp  al, 'A'
    jb   CheckLower
    cmp  al, 'F'
    jbe  IsUpper
CheckLower:
    cmp  al, 'a'
    jb   InvalidHex
    cmp  al, 'f'
    ja   InvalidHex
    sub  al, 'a'
    add  al, 10
    ret
HexIsDigit:
    sub  al, '0'
    ret
IsUpper:
    sub  al, 'A'
    add  al, 10
    ret
InvalidHex:
    mov  al, 0FFh
    ret
HexCharToNibble ENDP


; =========================================================
; ParseCommand
; =========================================================

ParseCommand PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]

    ; เช็กเฉพาะ 6 ตัวแรกสำหรับคำสั่ง KEYGEN
    mov  edi, OFFSET cmdKEYGEN
    mov  ecx, 6
    call StringPrefixEqual
    cmp  eax, 1
    je   FoundKEYGEN

    mov  edi, OFFSET cmdENCRYPT
    call StringEqual
    cmp  eax, 1
    je   FoundENCRYPT

    mov  edi, OFFSET cmdDECRYPT
    call StringEqual
    cmp  eax, 1
    je   FoundDECRYPT

    mov  edi, OFFSET cmdDUMP
    call StringEqual
    cmp  eax, 1
    je   FoundDUMP

    mov  edi, OFFSET cmdSTATS
    call StringEqual
    cmp  eax, 1
    je   FoundSTATS

    mov  edi, OFFSET cmdCLEAR
    call StringEqual
    cmp  eax, 1
    je   FoundCLEAR

    mov  edi, OFFSET cmdEXIT
    call StringEqual
    cmp  eax, 1
    je   FoundEXIT

    mov  eax, CMD_UNKNOWN
    jmp  ParseDone

FoundKEYGEN:
    mov  eax, CMD_KEYGEN
    jmp  ParseDone
FoundENCRYPT:
    mov  eax, CMD_ENCRYPT
    jmp  ParseDone
FoundDECRYPT:
    mov  eax, CMD_DECRYPT
    jmp  ParseDone
FoundDUMP:
    mov  eax, CMD_DUMP
    jmp  ParseDone
FoundSTATS:
    mov  eax, CMD_STATS
    jmp  ParseDone
FoundCLEAR:
    mov  eax, CMD_CLEAR
    jmp  ParseDone
FoundEXIT:
    mov  eax, CMD_EXIT

ParseDone:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4
ParseCommand ENDP


StringPrefixEqual PROC
    push ebx
    push ecx
    push esi
    push edi

PrefixLoop:
    cmp  ecx, 0
    je   PrefixEqual
    mov  al, [esi]
    mov  bl, [edi]
    cmp  al, bl
    jne  PrefixNotEqual
    inc  esi
    inc  edi
    dec  ecx
    jmp  PrefixLoop

PrefixEqual:
    mov  eax, 1
    jmp  PrefixDone
PrefixNotEqual:
    xor  eax, eax
PrefixDone:
    pop  edi
    pop  esi
    pop  ecx
    pop  ebx
    ret
StringPrefixEqual ENDP


StringEqual PROC
    push ebx
    push esi
    push edi

CompareLoop:
    mov  al, [esi]
    mov  bl, [edi]
    cmp  al, bl
    jne  NotEqual
    cmp  al, 0
    je   Equal
    inc  esi
    inc  edi
    jmp  CompareLoop

Equal:
    mov  eax, 1
    jmp  CompareDone
NotEqual:
    xor  eax, eax
CompareDone:
    pop  edi
    pop  esi
    pop  ebx
    ret
StringEqual ENDP

END main