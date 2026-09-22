TITLE DES Module A - Shell Core & FSM Command Parser

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

; =========================================================
; EXTERNAL PROTOTYPES (เชื่อมต่อ Module B และ C)
; =========================================================
GenerateKeySchedule PROTO :PTR BYTE, :PTR BYTE
DES_ProcessBlock    PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE, :DWORD


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
; ENCRYPT / DECRYPT BUFFERS & MESSAGES
; =========================================================
inFileName      BYTE 260 DUP(0)
outFileName     BYTE 260 DUP(0)
fileBuffer      BYTE 65536 DUP(0)    ; Buffer อ่านไฟล์ (สูงสุด 64KB)
encBuffer       BYTE 65536 DUP(0)    ; Buffer เก็บผลลัพธ์
fileHandle      HANDLE ?
fileSize        DWORD ?
paddedSize      DWORD ?

extEnc          BYTE ".enc", 0
extDec          BYTE ".dec", 0
msgEncSuccess   BYTE "File encrypted successfully -> ", 0
msgDecSuccess   BYTE "File decrypted successfully -> ", 0
msgFileError    BYTE "ERROR: Cannot open, read, or create file", 0Dh, 0Ah, 0
msgParamError   BYTE "ERROR: Invalid parameters. Usage: <CMD> <filename> <key>", 0Dh, 0Ah, 0
msgPadError     BYTE "ERROR: Invalid PKCS#7 Padding in decrypted data", 0Dh, 0Ah, 0


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


; =========================================================
; HANDLE ENCRYPT
; =========================================================
HandleEncrypt:
    mov  edx, OFFSET msgEncrypt
    call WriteString

    ; --- Step 1: Parse Filename และ Hex Key จาก inputBuffer ---
    mov  esi, OFFSET inputBuffer
    add  esi, 7                      ; ข้ามคำว่า "ENCRYPT"

SkipSpace1_Enc:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckQuote_Enc
    inc  esi
    jmp  SkipSpace1_Enc

CheckQuote_Enc:
    cmp  al, 0
    je   EncryptFailParams

    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  ParseNameNoQuote_Enc

    inc  esi                         ; ข้ามเครื่องหมาย "
ParseNameQuote_Enc:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneNameQuote_Enc
    cmp  al, 0
    je   EncryptFailParams
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameQuote_Enc
DoneNameQuote_Enc:
    inc  esi                         ; ข้ามเครื่องหมาย " ปิด
    jmp  TerminateInFile_Enc

ParseNameNoQuote_Enc:
    mov  al, [esi]
    cmp  al, ' '
    je   TerminateInFile_Enc
    cmp  al, 0
    je   TerminateInFile_Enc
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameNoQuote_Enc

TerminateInFile_Enc:
    mov  BYTE PTR [edi], 0           ; ปิดท้าย inFileName ด้วย Null-byte

    ; --- สร้างชื่อไฟล์ฝั่ง Output (inFileName + .enc) ---
    mov  ebx, OFFSET inFileName
    mov  edi, OFFSET outFileName
CopyNameLoop_Enc:
    mov  al, [ebx]
    cmp  al, 0
    je   AppendEnc_Enc
    mov  [edi], al
    inc  ebx
    inc  edi
    jmp  CopyNameLoop_Enc
AppendEnc_Enc:
    mov  ebx, OFFSET extEnc
AppendEncLoop_Enc:
    mov  al, [ebx]
    mov  [edi], al
    cmp  al, 0
    je   DoneOutName_Enc
    inc  ebx
    inc  edi
    jmp  AppendEncLoop_Enc
DoneOutName_Enc:

    ; --- เลื่อน Pointer ไปหา Hex Key ---
SkipSpace2_Enc:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckHexPrefix_Enc
    inc  esi
    jmp  SkipSpace2_Enc

CheckHexPrefix_Enc:
    cmp  al, 0
    je   EncryptFailParams
    cmp  al, '0'
    jne  StartKeyConversion_Enc
    mov  bl, [esi + 1]
    cmp  bl, 'x'
    je   SkipHexPrefix_Enc
    cmp  bl, 'X'
    jne  StartKeyConversion_Enc
SkipHexPrefix_Enc:
    add  esi, 2

StartKeyConversion_Enc:
    push OFFSET desKey
    push esi
    call ConvertHexKey
    cmp  eax, 1
    jne  EncryptFailKey

    ; --- Step 2: เรียก Module B สร้าง Subkeys 16 รอบ ---
    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  EncryptFailKey

    ; --- Step 3: อ่านไฟล์ Plaintext เข้า Memory ---
    mov  edx, OFFSET inFileName
    call OpenInputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   EncryptFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET fileBuffer
    mov  ecx, SIZEOF fileBuffer - 8
    mov  eax, fileHandle
    call ReadFromFile
    jc   CloseReadFail_Enc
    mov  fileSize, eax

    mov  eax, fileHandle
    call CloseFile

    ; --- Step 4: เติม PKCS#7 Padding ---
    mov  eax, fileSize
    xor  edx, edx
    mov  ebx, 8
    div  ebx                         ; EDX = fileSize % 8

    mov  eax, 8
    sub  eax, edx                    ; EAX = padLen (1 ถึง 8)
    mov  ecx, eax                    ; ECX = จำนวนไบต์ที่ต้องเติม

    mov  ebx, fileSize
    add  ebx, eax
    mov  paddedSize, ebx             ; paddedSize = fileSize + padLen

    mov  edi, OFFSET fileBuffer
    add  edi, fileSize               ; EDI ชี้ตำแหน่งท้ายข้อมูลเดิม
PadLoop:
    mov  [edi], cl                   ; เติมค่าไบต์เท่ากับ padLen
    inc  edi
    dec  eax
    jnz  PadLoop

    ; --- Step 5: Encrypt ทีละ 8 ไบต์ (ECB Mode) โดยใช้ Module C ---
    mov  esi, OFFSET fileBuffer
    mov  edi, OFFSET encBuffer
    mov  ecx, paddedSize
    shr  ecx, 3                      ; ECX = จำนวนบล็อก (paddedSize / 8)

EncryptBlockLoop:
    push ecx                         ; เก็บ Counter ไว้ใน Stack
    INVOKE DES_ProcessBlock, esi, edi, ADDR subKeys, 0
    add  esi, 8
    add  edi, 8
    pop  ecx
    dec  ecx                         ; ไม่ใช้ Directives ระดับสูง
    jnz  EncryptBlockLoop

    ; --- Step 6: เขียนข้อมูล Ciphertext ลงไฟล์ผลลัพธ์ (.enc) ---
    mov  edx, OFFSET outFileName
    call CreateOutputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   EncryptFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET encBuffer
    mov  ecx, paddedSize
    mov  eax, fileHandle
    call WriteToFile

    mov  eax, fileHandle
    call CloseFile

    ; --- แสดงผลการทำงานสำเร็จ ---
    mov  edx, OFFSET msgEncSuccess
    call WriteString
    mov  edx, OFFSET outFileName
    call WriteString
    mov  edx, OFFSET newline
    call WriteString

    jmp  MainLoop

CloseReadFail_Enc:
    mov  eax, fileHandle
    call CloseFile
EncryptFailFile:
    mov  edx, OFFSET msgFileError
    call WriteString
    jmp  MainLoop

EncryptFailParams:
    mov  edx, OFFSET msgParamError
    call WriteString
    jmp  MainLoop

EncryptFailKey:
    mov  edx, OFFSET msgKeyFail
    call WriteString
    jmp  MainLoop


; =========================================================
; HANDLE DECRYPT
; =========================================================
HandleDecrypt:
    mov  edx, OFFSET msgDecrypt
    call WriteString

    ; --- Step 1: Parse Filename และ Hex Key ---
    mov  esi, OFFSET inputBuffer
    add  esi, 7                      ; ข้ามคำว่า "DECRYPT"

SkipSpace1_Dec:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckQuote_Dec
    inc  esi
    jmp  SkipSpace1_Dec

CheckQuote_Dec:
    cmp  al, 0
    je   DecryptFailParams

    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  ParseNameNoQuote_Dec

    inc  esi
ParseNameQuote_Dec:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneNameQuote_Dec
    cmp  al, 0
    je   DecryptFailParams
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameQuote_Dec
DoneNameQuote_Dec:
    inc  esi
    jmp  TerminateInFile_Dec

ParseNameNoQuote_Dec:
    mov  al, [esi]
    cmp  al, ' '
    je   TerminateInFile_Dec
    cmp  al, 0
    je   TerminateInFile_Dec
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameNoQuote_Dec

TerminateInFile_Dec:
    mov  BYTE PTR [edi], 0

    ; --- สร้างชื่อไฟล์ฝั่ง Output (inFileName + .dec) ---
    mov  ebx, OFFSET inFileName
    mov  edi, OFFSET outFileName
CopyNameLoop_Dec:
    mov  al, [ebx]
    cmp  al, 0
    je   AppendDec_Dec
    mov  [edi], al
    inc  ebx
    inc  edi
    jmp  CopyNameLoop_Dec
AppendDec_Dec:
    mov  ebx, OFFSET extDec
AppendDecLoop_Dec:
    mov  al, [ebx]
    mov  [edi], al
    cmp  al, 0
    je   DoneOutName_Dec
    inc  ebx
    inc  edi
    jmp  AppendDecLoop_Dec
DoneOutName_Dec:

    ; --- เลื่อน Pointer ไปหา Hex Key ---
SkipSpace2_Dec:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckHexPrefix_Dec
    inc  esi
    jmp  SkipSpace2_Dec

CheckHexPrefix_Dec:
    cmp  al, 0
    je   DecryptFailParams
    cmp  al, '0'
    jne  StartKeyConversion_Dec
    mov  bl, [esi + 1]
    cmp  bl, 'x'
    je   SkipHexPrefix_Dec
    cmp  bl, 'X'
    jne  StartKeyConversion_Dec
SkipHexPrefix_Dec:
    add  esi, 2

StartKeyConversion_Dec:
    push OFFSET desKey
    push esi
    call ConvertHexKey
    cmp  eax, 1
    jne  DecryptFailKey

    ; --- Step 2: เรียก Module B สร้าง Subkeys ---
    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  DecryptFailKey

    ; --- Step 3: อ่านไฟล์ Ciphertext เข้า Memory ---
    mov  edx, OFFSET inFileName
    call OpenInputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   DecryptFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET fileBuffer
    mov  ecx, SIZEOF fileBuffer
    mov  eax, fileHandle
    call ReadFromFile
    jc   CloseReadFail_Dec
    mov  fileSize, eax

    mov  eax, fileHandle
    call CloseFile

    ; ตรวจสอบว่าไฟล์มีขนาดเป็นพหุคูณของ 8 หรือไม่
    mov  eax, fileSize
    cmp  eax, 0
    je   DecryptFailFile
    test eax, 7
    jnz  DecryptFailFile

    ; --- Step 4: Decrypt ทีละ 8 ไบต์ (ECB Mode, Mode = 1) ---
    mov  esi, OFFSET fileBuffer
    mov  edi, OFFSET encBuffer
    mov  ecx, fileSize
    shr  ecx, 3                      ; ECX = จำนวนบล็อก

DecryptBlockLoop:
    push ecx
    INVOKE DES_ProcessBlock, esi, edi, ADDR subKeys, 1
    add  esi, 8
    add  edi, 8
    pop  ecx
    dec  ecx
    jnz  DecryptBlockLoop

    ; --- Step 5: ตรวจสอบและตัด PKCS#7 Padding ---
    mov  esi, OFFSET encBuffer
    add  esi, fileSize
    dec  esi                         ; ESI ชี้ไบต์สุดท้าย
    movzx ecx, BYTE PTR [esi]        ; ECX = ค่า padLen (ไบต์สุดท้าย)

    cmp  ecx, 1
    jb   DecryptFailPad
    cmp  ecx, 8
    ja   DecryptFailPad

    mov  eax, fileSize
    sub  eax, ecx
    mov  paddedSize, eax             ; paddedSize ตอนนี้คือความยาวจริงหลังตัด Padding

    ; --- Step 6: เขียนข้อมูล Plaintext ลงไฟล์ผลลัพธ์ (.dec) ---
    mov  edx, OFFSET outFileName
    call CreateOutputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   DecryptFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET encBuffer
    mov  ecx, paddedSize
    mov  eax, fileHandle
    call WriteToFile

    mov  eax, fileHandle
    call CloseFile

    ; --- แสดงผลสำเร็จ ---
    mov  edx, OFFSET msgDecSuccess
    call WriteString
    mov  edx, OFFSET outFileName
    call WriteString
    mov  edx, OFFSET newline
    call WriteString

    jmp  MainLoop

CloseReadFail_Dec:
    mov  eax, fileHandle
    call CloseFile
DecryptFailFile:
    mov  edx, OFFSET msgFileError
    call WriteString
    jmp  MainLoop

DecryptFailParams:
    mov  edx, OFFSET msgParamError
    call WriteString
    jmp  MainLoop

DecryptFailKey:
    mov  edx, OFFSET msgKeyFail
    call WriteString
    jmp  MainLoop

DecryptFailPad:
    mov  edx, OFFSET msgPadError
    call WriteString
    jmp  MainLoop


; =========================================================
; PLACEHOLDERS FOR DUMP & STATS
; =========================================================

HandleDump:
    mov  edx, OFFSET msgDump
    call WriteString
    jmp  MainLoop

HandleStats:
    mov  edx, OFFSET msgStats
    call WriteString
    jmp  MainLoop

HandleClear:
    call Clrscr
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

    mov  eax, ebx
    imul eax, 6
    mov  esi, OFFSET subKeys
    add  esi, eax

    xor  ecx, ecx
ByteLoop:
    cmp  ecx, 6
    jge  ByteDone

    movzx eax, BYTE PTR [esi + ecx]

    push eax
    shr  eax, 4
    and  eax, 0Fh
    mov  al, hexDigits[eax]
    call WriteChar

    pop  eax
    and  eax, 0Fh
    mov  al, hexDigits[eax]
    call WriteChar

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

    mov  edi, OFFSET cmdKEYGEN
    mov  ecx, 6
    call StringPrefixEqual
    cmp  eax, 1
    je   FoundKEYGEN

    mov  edi, OFFSET cmdENCRYPT
    mov  ecx, 7
    call StringPrefixEqual
    cmp  eax, 1
    je   FoundENCRYPT

    mov  edi, OFFSET cmdDECRYPT
    mov  ecx, 7
    call StringPrefixEqual
    cmp  eax, 1
    je   FoundDECRYPT

    mov  edi, OFFSET cmdDUMP
    mov  ecx, 4
    call StringPrefixEqual
    cmp  eax, 1
    je   FoundDUMP

    mov  edi, OFFSET cmdSTATS
    mov  ecx, 5
    call StringPrefixEqual
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