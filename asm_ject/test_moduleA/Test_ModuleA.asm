TITLE DES Module A - Shell Core & FSM Command Parser (Strict Validation Version)

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib


; ============================================================
; Command constants
; ============================================================

CMD_UNKNOWN EQU 0
CMD_KEYGEN  EQU 1
CMD_ENCRYPT EQU 2
CMD_DECRYPT EQU 3
CMD_DUMP    EQU 4
CMD_STATS   EQU 5
CMD_CLEAR   EQU 6
CMD_EXIT    EQU 7


; ============================================================
; DATA
; ============================================================

.data

; ------------------------------------------------------------
; Prompt / messages
; ------------------------------------------------------------

prompt          BYTE "DES-SHELL> ",0

msgUnknown      BYTE "Error: Unknown command.",0Dh,0Ah,0

msgKeygen       BYTE "[KEYGEN command detected]",0Dh,0Ah,0
msgEncrypt      BYTE "[ENCRYPT command detected]",0Dh,0Ah,0
msgDecrypt      BYTE "[DECRYPT command detected]",0Dh,0Ah,0
msgDump         BYTE "[DUMP command detected]",0Dh,0Ah,0
msgStats        BYTE "[STATS command detected]",0Dh,0Ah,0
msgClear        BYTE "[CLEAR command detected]",0Dh,0Ah,0

msgFilename     BYTE "Filename: ",0
msgKey          BYTE "Key: ",0

newline         BYTE 0Dh,0Ah,0


; ------------------------------------------------------------
; Input buffer
; ------------------------------------------------------------

inputBuffer     BYTE 256 DUP(0)


; ------------------------------------------------------------
; Parser result
; ------------------------------------------------------------

commandType     DWORD CMD_UNKNOWN

filename        BYTE 256 DUP(0)

keyString       BYTE 32 DUP(0)


; ------------------------------------------------------------
; Command strings
; ------------------------------------------------------------

cmdKEYGEN       BYTE "KEYGEN",0
cmdENCRYPT      BYTE "ENCRYPT",0
cmdDECRYPT      BYTE "DECRYPT",0
cmdDUMP         BYTE "DUMP",0
cmdSTATS        BYTE "STATS",0
cmdCLEAR        BYTE "CLEAR",0
cmdEXIT         BYTE "EXIT",0


; ============================================================
; CODE
; ============================================================

.code


; ============================================================
; main
; ============================================================

main PROC

    push ebp
    mov ebp, esp

MainLoop:

    ; --------------------------------------------------------
    ; Display prompt
    ; --------------------------------------------------------

    mov edx, OFFSET prompt
    call WriteString


    ; --------------------------------------------------------
    ; Read command line
    ; --------------------------------------------------------

    mov edx, OFFSET inputBuffer
    mov ecx, SIZEOF inputBuffer - 1
    call ReadString


    ; --------------------------------------------------------
    ; Parse command line
    ; --------------------------------------------------------

    push OFFSET inputBuffer
    call ParseCommandLine


    ; --------------------------------------------------------
    ; Get parser result
    ; --------------------------------------------------------

    mov eax, commandType


    ; --------------------------------------------------------
    ; Dispatch command
    ; --------------------------------------------------------

    cmp eax, CMD_KEYGEN
    je HandleKeygen

    cmp eax, CMD_ENCRYPT
    je HandleEncrypt

    cmp eax, CMD_DECRYPT
    je HandleDecrypt

    cmp eax, CMD_DUMP
    je HandleDump

    cmp eax, CMD_STATS
    je HandleStats

    cmp eax, CMD_CLEAR
    je HandleClear

    cmp eax, CMD_EXIT
    je HandleExit


    ; --------------------------------------------------------
    ; Unknown command
    ; --------------------------------------------------------

    mov edx, OFFSET msgUnknown
    call WriteString

    jmp MainLoop


; ============================================================
; KEYGEN
; ============================================================

HandleKeygen:

    mov edx, OFFSET msgKeygen
    call WriteString

    mov edx, OFFSET msgKey
    call WriteString

    mov edx, OFFSET keyString
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    jmp MainLoop


; ============================================================
; ENCRYPT
; ============================================================

HandleEncrypt:

    mov edx, OFFSET msgEncrypt
    call WriteString

    mov edx, OFFSET msgFilename
    call WriteString

    mov edx, OFFSET filename
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    mov edx, OFFSET msgKey
    call WriteString

    mov edx, OFFSET keyString
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    jmp MainLoop


; ============================================================
; DECRYPT
; ============================================================

HandleDecrypt:

    mov edx, OFFSET msgDecrypt
    call WriteString

    mov edx, OFFSET msgFilename
    call WriteString

    mov edx, OFFSET filename
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    mov edx, OFFSET msgKey
    call WriteString

    mov edx, OFFSET keyString
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    jmp MainLoop


; ============================================================
; DUMP
; ============================================================

HandleDump:

    mov edx, OFFSET msgDump
    call WriteString

    mov edx, OFFSET msgFilename
    call WriteString

    mov edx, OFFSET filename
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    jmp MainLoop


; ============================================================
; STATS
; ============================================================

HandleStats:

    mov edx, OFFSET msgStats
    call WriteString

    mov edx, OFFSET msgFilename
    call WriteString

    mov edx, OFFSET filename
    call WriteString

    mov edx, OFFSET newline
    call WriteString

    jmp MainLoop


; ============================================================
; CLEAR
; ============================================================

HandleClear:

    call Clrscr

    jmp MainLoop


; ============================================================
; EXIT
; ============================================================

HandleExit:

    exit

main ENDP


; ============================================================
; ParseCommandLine
;
; Input:
;   [ebp+8] = address of input string
; ============================================================

ParseCommandLine PROC

    push ebp
    mov ebp, esp

    ; Preserve registers
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi


    ; --------------------------------------------------------
    ; Default command = UNKNOWN
    ; --------------------------------------------------------

    mov commandType, CMD_UNKNOWN


    ; --------------------------------------------------------
    ; Clear filename buffer
    ; --------------------------------------------------------

    mov edi, OFFSET filename
    mov ecx, SIZEOF filename

    mov al, 0

ClearFilename:

    mov BYTE PTR [edi], al

    inc edi

    loop ClearFilename


    ; --------------------------------------------------------
    ; Clear key buffer
    ; --------------------------------------------------------

    mov edi, OFFSET keyString
    mov ecx, SIZEOF keyString

    mov al, 0

ClearKey:

    mov BYTE PTR [edi], al

    inc edi

    loop ClearKey


    ; --------------------------------------------------------
    ; ESI = input string
    ; --------------------------------------------------------

    mov esi, [ebp+8]


    ; --------------------------------------------------------
    ; Skip leading spaces
    ; --------------------------------------------------------

    call SkipSpaces


    ; ========================================================
    ; Check KEYGEN
    ; ========================================================

    mov edi, OFFSET cmdKEYGEN

    call MatchWord

    cmp eax, 1
    je ParseKEYGEN


    ; ========================================================
    ; Check ENCRYPT
    ; ========================================================

    mov edi, OFFSET cmdENCRYPT

    call MatchWord

    cmp eax, 1
    je ParseENCRYPT


    ; ========================================================
    ; Check DECRYPT
    ; ========================================================

    mov edi, OFFSET cmdDECRYPT

    call MatchWord

    cmp eax, 1
    je ParseDECRYPT


    ; ========================================================
    ; Check DUMP
    ; ========================================================

    mov edi, OFFSET cmdDUMP

    call MatchWord

    cmp eax, 1
    je ParseDUMP


    ; ========================================================
    ; Check STATS
    ; ========================================================

    mov edi, OFFSET cmdSTATS

    call MatchWord

    cmp eax, 1
    je ParseSTATS


    ; ========================================================
    ; Check CLEAR
    ; ========================================================

    mov edi, OFFSET cmdCLEAR

    call MatchWord

    cmp eax, 1
    je ParseCLEAR


    ; ========================================================
    ; Check EXIT
    ; ========================================================

    mov edi, OFFSET cmdEXIT

    call MatchWord

    cmp eax, 1
    je ParseEXIT


    ; --------------------------------------------------------
    ; No command matched
    ; --------------------------------------------------------

    jmp ParseDone


; ============================================================
; Parse KEYGEN <key>
; ============================================================

ParseKEYGEN:

    call SkipSpaces

    mov edi, OFFSET keyString
    mov ecx, SIZEOF keyString - 1
    call CopyToken
    cmp eax, 0
    je ParseFailed

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov esi, OFFSET keyString
    call ValidateHexKey
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_KEYGEN
    jmp ParseDone


; ============================================================
; Parse ENCRYPT "<filename>" <key>
; ============================================================

ParseENCRYPT:

    call SkipSpaces

    mov edi, OFFSET filename
    mov ecx, SIZEOF filename - 1
    call CopyQuotedString
    cmp eax, 0
    je ParseFailed

    call SkipSpaces

    mov edi, OFFSET keyString
    mov ecx, SIZEOF keyString - 1
    call CopyToken
    cmp eax, 0
    je ParseFailed

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov esi, OFFSET keyString
    call ValidateHexKey
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_ENCRYPT
    jmp ParseDone


; ============================================================
; Parse DECRYPT "<filename>" <key>
; ============================================================

ParseDECRYPT:

    call SkipSpaces

    mov edi, OFFSET filename
    mov ecx, SIZEOF filename - 1
    call CopyQuotedString
    cmp eax, 0
    je ParseFailed

    call SkipSpaces

    mov edi, OFFSET keyString
    mov ecx, SIZEOF keyString - 1
    call CopyToken
    cmp eax, 0
    je ParseFailed

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov esi, OFFSET keyString
    call ValidateHexKey
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_DECRYPT
    jmp ParseDone


; ============================================================
; Parse DUMP "<filename>"
; ============================================================

ParseDUMP:

    call SkipSpaces

    mov edi, OFFSET filename
    mov ecx, SIZEOF filename - 1
    call CopyQuotedString
    cmp eax, 0
    je ParseFailed

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_DUMP
    jmp ParseDone


; ============================================================
; Parse STATS "<filename>"
; ============================================================

ParseSTATS:

    call SkipSpaces

    mov edi, OFFSET filename
    mov ecx, SIZEOF filename - 1
    call CopyQuotedString
    cmp eax, 0
    je ParseFailed

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_STATS
    jmp ParseDone


; ============================================================
; Parse CLEAR
; ============================================================

ParseCLEAR:

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_CLEAR
    jmp ParseDone


; ============================================================
; Parse EXIT
; ============================================================

ParseEXIT:

    call EnsureEndOfLine
    cmp eax, 0
    je ParseFailed

    mov commandType, CMD_EXIT
    jmp ParseDone


; ============================================================
; Parse Failed Rule
; ============================================================

ParseFailed:

    mov commandType, CMD_UNKNOWN


; ============================================================
; Parser finished
; ============================================================

ParseDone:

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

    mov esp, ebp
    pop ebp

    ret 4

ParseCommandLine ENDP


; ============================================================
; SkipSpaces
; ============================================================

SkipSpaces PROC

SkipSpacesLoop:

    mov al, BYTE PTR [esi]

    cmp al, ' '

    jne SkipSpacesDone

    inc esi

    jmp SkipSpacesLoop


SkipSpacesDone:

    ret

SkipSpaces ENDP


; ============================================================
; MatchWord
; ============================================================

MatchWord PROC

    push ebx
    push edx


    mov edx, esi


MatchLoop:

    mov al, BYTE PTR [esi]

    mov bl, BYTE PTR [edi]


    cmp bl, 0

    je CheckWordEnd


    cmp al, bl

    jne WordNotMatch


    inc esi
    inc edi

    jmp MatchLoop


CheckWordEnd:

    cmp al, 0

    je WordMatch


    cmp al, ' '

    je WordMatch


    jmp WordNotMatch


WordMatch:

    mov eax, 1

    pop edx
    pop ebx

    ret


WordNotMatch:

    mov esi, edx

    mov eax, 0

    pop edx
    pop ebx

    ret

MatchWord ENDP


; ============================================================
; EnsureEndOfLine
; Return: EAX = 1 (Clean End), EAX = 0 (Junk trailing characters)
; ============================================================

EnsureEndOfLine PROC

    call SkipSpaces

    mov al, BYTE PTR [esi]

    cmp al, 0
    jne EOL_Fail

    mov eax, 1
    ret

EOL_Fail:

    mov eax, 0
    ret

EnsureEndOfLine ENDP


; ============================================================
; CopyToken
; Return: EAX = 1 (Success), EAX = 0 (Empty)
; ============================================================

CopyToken PROC

    push ebx
    mov ebx, 0

CopyTokenLoop:

    cmp ecx, 0
    je CopyTokenCheck

    mov al, BYTE PTR [esi]

    cmp al, 0
    je CopyTokenCheck

    cmp al, ' '
    je CopyTokenCheck

    mov BYTE PTR [edi], al

    inc esi
    inc edi
    inc ebx
    dec ecx

    jmp CopyTokenLoop

CopyTokenCheck:

    mov BYTE PTR [edi], 0

    cmp ebx, 0
    je CopyTokenFail

    mov eax, 1
    pop ebx
    ret

CopyTokenFail:

    mov eax, 0
    pop ebx
    ret

CopyToken ENDP


; ============================================================
; CopyQuotedString
; Expected format: "filename.txt"
; Return: EAX = 1 (Success), EAX = 0 (Invalid Syntax/Empty)
; ============================================================

CopyQuotedString PROC

    call SkipSpaces

    mov al, BYTE PTR [esi]
    cmp al, '"'
    jne QuotedFail

    inc esi
    push edi

CopyQuotedLoop:

    cmp ecx, 0
    je QuotedFailPop

    mov al, BYTE PTR [esi]

    cmp al, 0
    je QuotedFailPop

    cmp al, '"'
    je QuotedClose

    mov BYTE PTR [edi], al

    inc esi
    inc edi
    dec ecx

    jmp CopyQuotedLoop

QuotedClose:

    mov BYTE PTR [edi], 0
    inc esi

    pop ebx
    cmp edi, ebx
    je QuotedFail

    mov eax, 1
    ret

QuotedFailPop:

    pop ebx

QuotedFail:

    mov BYTE PTR [edi], 0
    mov eax, 0
    ret

CopyQuotedString ENDP


; ============================================================
; ValidateHexKey
; Checks if keyString is a valid 64-bit Hex key (16 hex chars / 0x prefix)
; Return: EAX = 1 (Valid), EAX = 0 (Invalid)
; ============================================================

ValidateHexKey PROC

    push ebx
    push ecx
    push edx
    push esi

    mov al, BYTE PTR [esi]
    cmp al, '0'
    jne CheckLoopStart

    mov al, BYTE PTR [esi + 1]
    cmp al, 'x'
    je SkipPrefix
    cmp al, 'X'
    jne CheckLoopStart

SkipPrefix:

    add esi, 2

CheckLoopStart:

    mov ecx, 0


ValHexLoop:

    mov al, BYTE PTR [esi]

    cmp al, 0
    je ValHexDone


    cmp al, '0'
    jb CheckUpper
    cmp al, '9'
    jbe ValidChar


CheckUpper:

    cmp al, 'A'
    jb CheckLower
    cmp al, 'F'
    jbe ValidChar


CheckLower:

    cmp al, 'a'
    jb ValHexFail
    cmp al, 'f'
    ja ValHexFail


ValidChar:

    inc ecx
    inc esi
    jmp ValHexLoop


ValHexDone:

    cmp ecx, 16
    jne ValHexFail

    mov eax, 1
    jmp ValHexExit


ValHexFail:

    mov eax, 0


ValHexExit:

    pop esi
    pop edx
    pop ecx
    pop ebx

    ret

ValidateHexKey ENDP


END main