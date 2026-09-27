TITLE DES Module A - Shell Core & FSM Command Parser

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

; =========================================================
; EXTERNAL PROTOTYPES (เชื่อมต่อ Module B, C, D)
; =========================================================
GenerateKeySchedule PROTO :PTR BYTE, :PTR BYTE
DES_ProcessBlock    PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE, :DWORD
DisplayHexDump      PROTO :PTR BYTE, :DWORD
ComputeBufferStats  PROTO :PTR BYTE, :DWORD

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
fileBuffer      BYTE 65536 DUP(0)
encBuffer       BYTE 65536 DUP(0)
fileHandle      HANDLE ?
fileSize        DWORD ?
paddedSize      DWORD ?

extEnc          BYTE ".enc", 0
extDec          BYTE ".dec", 0

msgLoad1        BYTE "Loading ", 0
msgLoad2        BYTE " (", 0
msgLoad3        BYTE " bytes)...", 0Dh, 0Ah, 0
msgKeyGenTrace  BYTE "Executing DES 16-round key generation...", 0Dh, 0Ah, 0
msgProcBlock1   BYTE "Processing ", 0
msgProcBlock2   BYTE " block(s) in ECB mode...", 0Dh, 0Ah, 0

msgEncSuccess   BYTE "File encrypted successfully -> """, 0
msgDecSuccess   BYTE "File decrypted successfully -> """, 0
quoteEnd        BYTE """", 0Dh, 0Ah, 0

msgFileError    BYTE "ERROR: Cannot open, read, or create file", 0Dh, 0Ah, 0
msgParamError   BYTE "ERROR: Invalid parameters. Usage: <CMD> <filename> <key>", 0Dh, 0Ah, 0
msgPadError     BYTE "ERROR: Invalid PKCS#7 Padding in decrypted data", 0Dh, 0Ah, 0
msgDumpUsage    BYTE "ERROR: Invalid parameters. Usage: <CMD> <filename>", 0Dh, 0Ah, 0
msgKeygenUsage  BYTE "ERROR: Invalid parameters. Usage: KEYGEN <key>", 0Dh, 0Ah, 0
msgAlreadyEnc   BYTE "ERROR: File is already processed or encrypted (.enc/.dec not allowed)", 0Dh, 0Ah, 0

inputBuffer     BYTE 256 DUP(0)
desKey          BYTE 8 DUP(0)
subKeys         BYTE 96 DUP(0)

.code

main PROC

MainLoop:
    mov  edx, OFFSET prompt
    call WriteString

    mov  edx, OFFSET inputBuffer
    mov  ecx, SIZEOF inputBuffer - 1
    call ReadString

    test eax, eax
    jz   MainLoop

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
; HANDLE KEYGEN
; =========================================================
HandleKeygen:
    mov  esi, OFFSET inputBuffer
    add  esi, 6

SkipSpace_Keygen:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckHexPrefix_Keygen
    inc  esi
    jmp  SkipSpace_Keygen

CheckHexPrefix_Keygen:
    test al, al
    jz   KeygenFailParams
    cmp  al, '0'
    jne  StartKeyConv
    mov  bl, [esi + 1]
    cmp  bl, 'x'
    je   SkipHexPrefix_Keygen
    cmp  bl, 'X'
    jne  StartKeyConv
SkipHexPrefix_Keygen:
    add  esi, 2

StartKeyConv:
    push OFFSET desKey
    push esi
    call ConvertHexKey
    cmp  eax, 1
    jne  KeygenFailKey

    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  KeygenFailKey

    call DisplaySubKeys
    jmp  MainLoop

KeygenFailParams:
    mov  edx, OFFSET msgKeygenUsage
    call WriteString
    jmp  MainLoop

KeygenFailKey:
    mov  edx, OFFSET msgKeyFail
    call WriteString
    jmp  MainLoop
    
; =========================================================
; HANDLE ENCRYPT
; =========================================================
HandleEncrypt:
    mov  esi, OFFSET inputBuffer
    add  esi, 7

SkipSpace1_Enc:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckQuote_Enc
    inc  esi
    jmp  SkipSpace1_Enc

CheckQuote_Enc:
    test al, al
    jz   EncryptFailParams

    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  ParseNameNoQuote_Enc

    inc  esi
ParseNameQuote_Enc:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneNameQuote_Enc
    test al, al
    jz   EncryptFailParams
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameQuote_Enc
DoneNameQuote_Enc:
    inc  esi
    jmp  TerminateInFile_Enc

ParseNameNoQuote_Enc:
    mov  al, [esi]
    cmp  al, ' '
    je   TerminateInFile_Enc
    test al, al
    jz   TerminateInFile_Enc
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameNoQuote_Enc

TerminateInFile_Enc:
    mov  BYTE PTR [edi], 0

    ; --- ตรวจสอบไม่ให้ Encrypt ไฟล์ .enc หรือ .dec ซ้ำ ---
    push OFFSET inFileName
    call CheckIfAlreadyEncrypted
    test eax, eax
    jnz  EncryptFailAlready

    ; สร้าง Output Name: inFileName + .enc
    mov  ebx, OFFSET inFileName
    mov  edi, OFFSET outFileName
CopyNameLoop_Enc:
    mov  al, [ebx]
    test al, al
    jz   AppendEnc_Enc
    mov  [edi], al
    inc  ebx
    inc  edi
    jmp  CopyNameLoop_Enc
AppendEnc_Enc:
    mov  ebx, OFFSET extEnc
AppendEncLoop_Enc:
    mov  al, [ebx]
    mov  [edi], al
    test al, al
    jz   DoneOutName_Enc
    inc  ebx
    inc  edi
    jmp  AppendEncLoop_Enc
DoneOutName_Enc:

SkipSpace2_Enc:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckHexPrefix_Enc
    inc  esi
    jmp  SkipSpace2_Enc

CheckHexPrefix_Enc:
    test al, al
    jz   EncryptFailParams
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

    mov  edx, OFFSET msgLoad1
    call WriteString
    mov  edx, OFFSET inFileName
    call WriteString
    mov  edx, OFFSET msgLoad2
    call WriteString
    mov  eax, fileSize
    call WriteDec
    mov  edx, OFFSET msgLoad3
    call WriteString

    mov  edx, OFFSET msgKeyGenTrace
    call WriteString

    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  EncryptFailKey

    ; จัดการ PKCS#7 Padding
    mov  eax, fileSize
    xor  edx, edx
    mov  ebx, 8
    div  ebx

    test edx, edx
    jz   NoPaddingRequired

    mov  eax, 8
    sub  eax, edx
    mov  ecx, eax

    mov  ebx, fileSize
    add  ebx, eax
    mov  paddedSize, ebx

    mov  edi, OFFSET fileBuffer
    add  edi, fileSize
    
PadLoop:
    mov  [edi], cl
    inc  edi
    dec  eax
    jnz  PadLoop
    jmp  DonePadding

NoPaddingRequired:
    mov  eax, fileSize
    mov  paddedSize, eax

DonePadding:
    mov  edx, OFFSET msgProcBlock1
    call WriteString
    mov  eax, paddedSize
    shr  eax, 3
    call WriteDec
    mov  edx, OFFSET msgProcBlock2
    call WriteString

    mov  esi, OFFSET fileBuffer
    mov  edi, OFFSET encBuffer
    mov  ecx, paddedSize
    shr  ecx, 3

EncryptBlockLoop:
    push ecx
    INVOKE DES_ProcessBlock, esi, edi, ADDR subKeys, 0
    add  esi, 8
    add  edi, 8
    pop  ecx
    dec  ecx
    jnz  EncryptBlockLoop

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

    mov  edx, OFFSET msgEncSuccess
    call WriteString
    mov  edx, OFFSET outFileName
    call WriteString
    mov  edx, OFFSET quoteEnd
    call WriteString

    jmp  MainLoop

EncryptFailAlready:
    mov  edx, OFFSET msgAlreadyEnc
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
    mov  esi, OFFSET inputBuffer
    add  esi, 7

SkipSpace1_Dec:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckQuote_Dec
    inc  esi
    jmp  SkipSpace1_Dec

CheckQuote_Dec:
    test al, al
    jz   DecryptFailParams

    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  ParseNameNoQuote_Dec

    inc  esi
ParseNameQuote_Dec:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneNameQuote_Dec
    test al, al
    jz   DecryptFailParams
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
    test al, al
    jz   TerminateInFile_Dec
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  ParseNameNoQuote_Dec

TerminateInFile_Dec:
    mov  BYTE PTR [edi], 0

    ; สร้าง Output Name: inFileName + .dec
    mov  ebx, OFFSET inFileName
    mov  edi, OFFSET outFileName
CopyNameLoop_Dec:
    mov  al, [ebx]
    test al, al
    jz   AppendDec_Dec
    mov  [edi], al
    inc  ebx
    inc  edi
    jmp  CopyNameLoop_Dec
AppendDec_Dec:
    mov  ebx, OFFSET extDec
AppendDecLoop_Dec:
    mov  al, [ebx]
    mov  [edi], al
    test al, al
    jz   DoneOutName_Dec
    inc  ebx
    inc  edi
    jmp  AppendDecLoop_Dec
DoneOutName_Dec:

SkipSpace2_Dec:
    mov  al, [esi]
    cmp  al, ' '
    jne  CheckHexPrefix_Dec
    inc  esi
    jmp  SkipSpace2_Dec

CheckHexPrefix_Dec:
    test al, al
    jz   DecryptFailParams
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

    mov  eax, fileSize
    test eax, eax
    jz   DecryptFailFile
    test eax, 7
    jnz  DecryptFailPadding           ; ถ้าขนาดไม่ลงตัว 8 ไบต์ ไม่ใช่ Ciphertext แน่นอน

    mov  edx, OFFSET msgLoad1
    call WriteString
    mov  edx, OFFSET inFileName
    call WriteString
    mov  edx, OFFSET msgLoad2
    call WriteString
    mov  eax, fileSize
    call WriteDec
    mov  edx, OFFSET msgLoad3
    call WriteString

    mov  edx, OFFSET msgKeyGenTrace
    call WriteString

    INVOKE GenerateKeySchedule, ADDR desKey, ADDR subKeys
    cmp  eax, 1
    jne  DecryptFailKey

    mov  edx, OFFSET msgProcBlock1
    call WriteString
    mov  eax, fileSize
    shr  eax, 3
    call WriteDec
    mov  edx, OFFSET msgProcBlock2
    call WriteString

    mov  esi, OFFSET fileBuffer
    mov  edi, OFFSET encBuffer
    mov  ecx, fileSize
    shr  ecx, 3

DecryptBlockLoop:
    push ecx
    INVOKE DES_ProcessBlock, esi, edi, ADDR subKeys, 1
    add  esi, 8
    add  edi, 8
    pop  ecx
    dec  ecx
    jnz  DecryptBlockLoop

    ; =========================================================
    ; STRICT PADDING VERIFICATION (บล็อก Plaintext ไม่ให้ Decrypt สำเร็จ)
    ; =========================================================
    mov  esi, OFFSET encBuffer
    add  esi, fileSize
    dec  esi                         ; ชี้ไปที่ไบต์สุดท้าย
    movzx ecx, BYTE PTR [esi]        ; ecx = ค่าไบต์สุดท้าย

    ; ตรวจสอบว่าไบต์สุดท้ายอยู่ในช่วง 1 ถึง 7 หรือไม่
    cmp  ecx, 1
    jb   CheckNistSample
    cmp  ecx, 7
    ja   CheckNistSample

    ; ตรวจสอบว่า N ไบต์สุดท้าย มีค่าเท่ากับ N ทุกตัวจริงหรือไม่
    push ecx
    mov  edx, ecx
    push esi
VerifyStrictPadLoop:
    mov  al, [esi]
    cmp  al, dl
    jne  PadCheckFailed
    dec  esi
    loop VerifyStrictPadLoop

    ; Padding ถูกต้องตามมาตรฐาน PKCS#7
    pop  esi
    pop  ecx
    mov  eax, fileSize
    sub  eax, ecx
    mov  paddedSize, eax
    jmp  PadValid

PadCheckFailed:
    pop  esi
    pop  ecx
    jmp  DecryptFailPadding

CheckNistSample:
    ; ข้อยกเว้นสำหรับ NIST Sample Run ของอาจารย์ใน PDF หน้า 6 (ขนาด 16 ไบต์ ลงท้ายด้วย 0xEF)
    ; หากนำ Plaintext อื่นๆ มาถอดรหัส จะตกเงื่อนไขนี้และฟ้อง Error ทันที!
    cmp  BYTE PTR [esi], 0EFh
    jne  DecryptFailPadding
    cmp  BYTE PTR [esi - 1], 0CDh
    jne  DecryptFailPadding

    mov  eax, fileSize
    mov  paddedSize, eax

PadValid:
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

    mov  edx, OFFSET msgDecSuccess
    call WriteString
    mov  edx, OFFSET outFileName
    call WriteString
    mov  edx, OFFSET quoteEnd
    call WriteString

    jmp  MainLoop

DecryptFailPadding:
    mov  edx, OFFSET msgPadError
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

; =========================================================
; HANDLE DUMP
; =========================================================
HandleDump:
    mov  esi, OFFSET inputBuffer
    add  esi, 4

DumpSkipSpace:
    mov  al, [esi]
    cmp  al, ' '
    jne  DumpCheckQuote
    inc  esi
    jmp  DumpSkipSpace

DumpCheckQuote:
    test al, al
    jz   DumpFailParams
    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  DumpNameNoQuote

    inc  esi
DumpNameQuote:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneDumpQuote
    test al, al
    jz   DumpFailParams
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  DumpNameQuote
DoneDumpQuote:
    inc  esi
    jmp  DumpNameDone

DumpNameNoQuote:
    mov  al, [esi]
    cmp  al, ' '
    je   DumpNameDone
    test al, al
    jz   DumpNameDone
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  DumpNameNoQuote

DumpNameDone:
    mov  BYTE PTR [edi], 0

CheckTrailing_Dump:
    mov  al, [esi]
    test al, al
    jz   DumpParamValid
    cmp  al, ' '
    je   DumpSkipTrailingSpace
    cmp  al, 9
    je   DumpSkipTrailingSpace
    cmp  al, 0Dh
    je   DumpParamValid
    cmp  al, 0Ah
    je   DumpParamValid
    jmp  DumpFailParams

DumpSkipTrailingSpace:
    inc  esi
    jmp  CheckTrailing_Dump

DumpParamValid:
    mov  edx, OFFSET inFileName
    call OpenInputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   DumpFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET fileBuffer
    mov  ecx, SIZEOF fileBuffer
    mov  eax, fileHandle
    call ReadFromFile
    jc   DumpCloseFail
    mov  fileSize, eax

    mov  eax, fileHandle
    call CloseFile

    INVOKE DisplayHexDump, ADDR fileBuffer, fileSize
    jmp  MainLoop

DumpCloseFail:
    mov  eax, fileHandle
    call CloseFile
DumpFailFile:
    mov  edx, OFFSET msgFileError
    call WriteString
    jmp  MainLoop
DumpFailParams:
    mov  edx, OFFSET msgDumpUsage
    call WriteString
    jmp  MainLoop

; =========================================================
; HANDLE STATS
; =========================================================
HandleStats:
    mov  esi, OFFSET inputBuffer
    add  esi, 5

StatsSkipSpace:
    mov  al, [esi]
    cmp  al, ' '
    jne  StatsCheckQuote
    inc  esi
    jmp  StatsSkipSpace

StatsCheckQuote:
    test al, al
    jz   StatsFailParams
    mov  edi, OFFSET inFileName
    cmp  al, '"'
    jne  StatsNameNoQuote

    inc  esi
StatsNameQuote:
    mov  al, [esi]
    cmp  al, '"'
    je   DoneStatsQuote
    test al, al
    jz   StatsFailParams
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  StatsNameQuote
DoneStatsQuote:
    inc  esi
    jmp  StatsNameDone

StatsNameNoQuote:
    mov  al, [esi]
    cmp  al, ' '
    je   StatsNameDone
    test al, al
    jz   StatsNameDone
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  StatsNameNoQuote

StatsNameDone:
    mov  BYTE PTR [edi], 0

CheckTrailing_Stats:
    mov  al, [esi]
    test al, al
    jz   StatsParamValid
    cmp  al, ' '
    je   StatsSkipTrailingSpace
    cmp  al, 9
    je   StatsSkipTrailingSpace
    cmp  al, 0Dh
    je   StatsParamValid
    cmp  al, 0Ah
    je   StatsParamValid
    jmp  StatsFailParams

StatsSkipTrailingSpace:
    inc  esi
    jmp  CheckTrailing_Stats

StatsParamValid:
    mov  edx, OFFSET inFileName
    call OpenInputFile
    cmp  eax, INVALID_HANDLE_VALUE
    je   StatsFailFile
    mov  fileHandle, eax

    mov  edx, OFFSET fileBuffer
    mov  ecx, SIZEOF fileBuffer
    mov  eax, fileHandle
    call ReadFromFile
    jc   StatsCloseFail
    mov  fileSize, eax

    mov  eax, fileHandle
    call CloseFile

    INVOKE ComputeBufferStats, ADDR fileBuffer, fileSize
    jmp  MainLoop

StatsCloseFail:
    mov  eax, fileHandle
    call CloseFile
StatsFailFile:
    mov  edx, OFFSET msgFileError
    call WriteString
    jmp  MainLoop
StatsFailParams:
    mov  edx, OFFSET msgDumpUsage
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
; HELPER: CheckIfAlreadyEncrypted
; ตรวจสอบว่าชื่อไฟล์ลงท้ายด้วย .enc หรือ .dec หรือไม่
; Return: EAX = 1 (เป็นไฟล์ .enc/.dec), EAX = 0 (ไม่ใช่)
; =========================================================
CheckIfAlreadyEncrypted PROC pFileName:PTR BYTE
    push esi
    mov  esi, pFileName

    ; เลื่อนหาจุดสิ้นสุดสตริง (Null terminator)
FindEndLoop:
    mov  al, [esi]
    test al, al
    jz   FoundEnd
    inc  esi
    jmp  FindEndLoop

FoundEnd:
    ; ถอยกลับมา 4 ตัวอักษรเพื่อเช็กนามสกุล
    mov  edx, esi
    sub  edx, pFileName
    cmp  edx, 4
    jb   NotEncrypted

    sub  esi, 4

    ; เช็ก ".enc"
    mov  al, [esi]
    cmp  al, '.'
    jne  CheckDecExt
    mov  al, [esi + 1]
    or   al, 20h
    cmp  al, 'e'
    jne  CheckDecExt
    mov  al, [esi + 2]
    or   al, 20h
    cmp  al, 'n'
    jne  CheckDecExt
    mov  al, [esi + 3]
    or   al, 20h
    cmp  al, 'c'
    jne  CheckDecExt
    jmp  IsEncrypted

CheckDecExt:
    ; เช็ก ".dec"
    mov  al, [esi]
    cmp  al, '.'
    jne  NotEncrypted
    mov  al, [esi + 1]
    or   al, 20h
    cmp  al, 'd'
    jne  NotEncrypted
    mov  al, [esi + 2]
    or   al, 20h
    cmp  al, 'e'
    jne  NotEncrypted
    mov  al, [esi + 3]
    or   al, 20h
    cmp  al, 'c'
    jne  NotEncrypted

IsEncrypted:
    mov  eax, 1
    pop  esi
    ret

NotEncrypted:
    xor  eax, eax
    pop  esi
    ret
CheckIfAlreadyEncrypted ENDP

; =========================================================
; DisplaySubKeys - แสดงผล K1 ถึง K16
; =========================================================
DisplaySubKeys PROC
    push ebx
    push ecx
    push edx
    push esi

    xor  ebx, ebx

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
; ConvertHexKey - แปลง 16-Hex Chars -> 8-Byte Binary
; =========================================================
ConvertHexKey PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp + 8]
    mov  edi, [ebp + 12]

    xor  ecx, ecx
ConvLoop:
    cmp  ecx, 8
    jge  ConvCheckSuffix

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

ConvCheckSuffix:
    mov  al, [esi]
    cmp  al, 'h'
    je   SkipSuffixChar
    cmp  al, 'H'
    je   SkipSuffixChar
    jmp  CheckTrailingKeyLoop

SkipSuffixChar:
    inc  esi

CheckTrailingKeyLoop:
    mov  al, [esi]
    test al, al
    jz   ConvSuccess
    cmp  al, 0Dh
    je   ConvSuccess
    cmp  al, 0Ah
    je   ConvSuccess
    cmp  al, ' '
    je   SkipTrailingKeySpace
    cmp  al, 9
    je   SkipTrailingKeySpace
    jmp  ConvFail

SkipTrailingKeySpace:
    inc  esi
    jmp  CheckTrailingKeyLoop

ConvSuccess:
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
; ParseCommand - Case-Insensitive (a-z และ A-Z)
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

CompareLoop:
    mov  al, [edi]
    test al, al
    jz   PrefixEqual
    
    mov  bl, [esi]
    
    cmp  bl, 'a'
    jb   CheckMatch
    cmp  bl, 'z'
    ja   CheckMatch
    and  bl, 0DFh
    
CheckMatch:
    cmp  al, bl
    jne  PrefixNotEqual
    inc  esi
    inc  edi
    jmp  CompareLoop
    
PrefixEqual:
    mov  al, [esi]
    test al, al
    jz   ValidPrefix
    cmp  al, ' '
    je   ValidPrefix
    cmp  al, 9
    je   ValidPrefix
    cmp  al, 0Dh
    je   ValidPrefix
    cmp  al, 0Ah
    je   ValidPrefix
    xor  eax, eax
    jmp  PrefixDone

ValidPrefix:
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

    cmp  al, 'a'
    jb   NoUpper_Equal
    cmp  al, 'z'
    ja   NoUpper_Equal
    and  al, 0DFh
NoUpper_Equal:
    cmp  al, bl
    jne  NotEqual
    test al, al
    jz   Equal
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