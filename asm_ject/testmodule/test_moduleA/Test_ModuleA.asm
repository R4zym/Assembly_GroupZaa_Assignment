TITLE DES Module A - Shell Core & FSM Command Parser

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib


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
; STRINGS
; =========================================================

prompt          BYTE "DES-SHELL> ", 0

msgKeygen       BYTE "[KEYGEN command detected]", 0Dh, 0Ah, 0
msgEncrypt      BYTE "[ENCRYPT command detected]", 0Dh, 0Ah, 0
msgDecrypt      BYTE "[DECRYPT command detected]", 0Dh, 0Ah, 0
msgDump         BYTE "[DUMP command detected]", 0Dh, 0Ah, 0
msgStats        BYTE "[STATS command detected]", 0Dh, 0Ah, 0
msgClear        BYTE "[CLEAR command detected]", 0Dh, 0Ah, 0

msgUnknown      BYTE "ERROR: Unknown command", 0Dh, 0Ah, 0
msgExit         BYTE "Exiting DES Command-Line Shell...", 0Dh, 0Ah, 0


; =========================================================
; INPUT BUFFER
; =========================================================

inputBuffer     BYTE 256 DUP(0)


.code


; =========================================================
; MAIN
; =========================================================

main PROC

    push ebp
    mov  ebp, esp

MainLoop:

    ; -----------------------------------------------------
    ; แสดง prompt
    ; -----------------------------------------------------

    mov  edx, OFFSET prompt
    call WriteString


    ; -----------------------------------------------------
    ; รับ command จาก user
    ; -----------------------------------------------------

    mov  edx, OFFSET inputBuffer
    mov  ecx, SIZEOF inputBuffer - 1
    call ReadString


    ; -----------------------------------------------------
    ; Parse command
    ;
    ; EAX = command ID
    ; -----------------------------------------------------

    push OFFSET inputBuffer
    call ParseCommand


    ; -----------------------------------------------------
    ; ตรวจว่า command คืออะไร
    ; -----------------------------------------------------

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


    ; -----------------------------------------------------
    ; ไม่รู้จัก command
    ; -----------------------------------------------------

    mov  edx, OFFSET msgUnknown
    call WriteString

    jmp  MainLoop


; =========================================================
; COMMAND HANDLERS
; =========================================================

HandleKeygen:

    mov  edx, OFFSET msgKeygen
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

    ; ตอนนี้ยังไม่ต้องทำ clear จริง
    ; เอาไว้ทำในขั้นต่อไป

    jmp  MainLoop


HandleExit:

    mov  edx, OFFSET msgExit
    call WriteString

    mov  esp, ebp
    pop  ebp

    exit

main ENDP



; =========================================================
; ParseCommand
;
; Input:
;   [ebp + 8] = pointer ไปยัง input string
;
; Return:
;   EAX = command ID
;
; CMD_UNKNOWN = 0
; CMD_KEYGEN  = 1
; CMD_ENCRYPT = 2
; CMD_DECRYPT = 3
; CMD_DUMP    = 4
; CMD_STATS   = 5
; CMD_CLEAR   = 6
; CMD_EXIT    = 7
;
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


; =========================================================
; Check KEYGEN
; =========================================================

    mov  edi, OFFSET cmdKEYGEN
    call StringEqual

    cmp  eax, 1
    je   FoundKEYGEN


; =========================================================
; Check ENCRYPT
; =========================================================

    mov  edi, OFFSET cmdENCRYPT
    call StringEqual

    cmp  eax, 1
    je   FoundENCRYPT


; =========================================================
; Check DECRYPT
; =========================================================

    mov  edi, OFFSET cmdDECRYPT
    call StringEqual

    cmp  eax, 1
    je   FoundDECRYPT


; =========================================================
; Check DUMP
; =========================================================

    mov  edi, OFFSET cmdDUMP
    call StringEqual

    cmp  eax, 1
    je   FoundDUMP


; =========================================================
; Check STATS
; =========================================================

    mov  edi, OFFSET cmdSTATS
    call StringEqual

    cmp  eax, 1
    je   FoundSTATS


; =========================================================
; Check CLEAR
; =========================================================

    mov  edi, OFFSET cmdCLEAR
    call StringEqual

    cmp  eax, 1
    je   FoundCLEAR


; =========================================================
; Check EXIT
; =========================================================

    mov  edi, OFFSET cmdEXIT
    call StringEqual

    cmp  eax, 1
    je   FoundEXIT


; =========================================================
; Unknown
; =========================================================

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
    
    pop edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx

    mov  esp, ebp
    pop  ebp

    ret 4

ParseCommand ENDP



; =========================================================
; StringEqual
;
; เปรียบเทียบ string
;
; Input:
;   ESI = string จาก user
;   EDI = string ที่ต้องการเปรียบเทียบ
;
; Return:
;   EAX = 1 ถ้าเหมือน
;   EAX = 0 ถ้าไม่เหมือน
;
; =========================================================

StringEqual PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi
    push edi


CompareLoop:

    mov  al, BYTE PTR [esi]
    mov  bl, BYTE PTR [edi]


    ; -----------------------------------------------------
    ; ตัวอักษรไม่เหมือนกัน
    ; -----------------------------------------------------

    cmp  al, bl
    jne  StringsNotEqual


    ; -----------------------------------------------------
    ; ถ้าเจอ NULL ทั้งคู่ แปลว่าเหมือนกัน
    ; -----------------------------------------------------

    cmp  al, 0
    je   StringsEqual


    inc  esi
    inc  edi

    jmp  CompareLoop


StringsEqual:

    mov  eax, 1
    jmp  StringCompareDone


StringsNotEqual:

    mov  eax, 0


StringCompareDone:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx

    mov  esp, ebp
    pop  ebp

    ret

StringEqual ENDP



; =========================================================
; COMMAND STRINGS
; =========================================================

cmdKEYGEN   BYTE "KEYGEN", 0
cmdENCRYPT  BYTE "ENCRYPT", 0
cmdDECRYPT  BYTE "DECRYPT", 0
cmdDUMP     BYTE "DUMP", 0
cmdSTATS    BYTE "STATS", 0
cmdCLEAR    BYTE "CLEAR", 0
cmdEXIT     BYTE "EXIT", 0


END main