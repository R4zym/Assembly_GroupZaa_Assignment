TITLE DES Module B - Key Schedule Generator

INCLUDE Irvine32.inc

.386
.model flat, stdcall


.data

; =========================================================
; INPUT
; =========================================================

keyInput BYTE 32 DUP(0)
Key64    BYTE 8 DUP(0)

promptKey BYTE "Enter 64-bit DES Key (16 hex): ",0
msgOK     BYTE 0Dh,0Ah,"Key accepted.",0Dh,0Ah,0
msgErr    BYTE 0Dh,0Ah,"Invalid DES key.",0Dh,0Ah,0


; =========================================================
; DES PC-1
; =========================================================

PC1 BYTE 57,49,41,33,25,17,9,1
    BYTE 58,50,42,34,26,18,10,2
    BYTE 59,51,43,35,27,19,11,3
    BYTE 60,52,44,36,63,55,47,39
    BYTE 31,23,15,7,62,54,46,38
    BYTE 30,22,14,6,61,53,45,37
    BYTE 29,21,13,5,28,20,12,4


; =========================================================
; DES LEFT SHIFT SCHEDULE
; =========================================================

ShiftSchedule BYTE 1,1,2,2,2,2,2,2
               BYTE 1,2,2,2,2,2,2,1


; =========================================================
; DES PC-2
; =========================================================

PC2 BYTE 14,17,11,24,1,5
    BYTE 3,28,15,6,21,10
    BYTE 23,19,12,4,26,8
    BYTE 16,7,27,20,13,2
    BYTE 41,52,31,37,47,55
    BYTE 30,40,51,45,33,48
    BYTE 44,49,39,56,34,53
    BYTE 46,42,50,36,29,32


; =========================================================
; WORKING VARIABLES
; =========================================================

C DWORD ?
D DWORD ?

; 16 rounds × 6 bytes
SubKeys BYTE 96 DUP(?)


.code

main PROC

    ; =====================================================
    ; STEP 1 : INPUT KEY
    ; =====================================================

    mov edx, OFFSET promptKey
    call WriteString

    mov edx, OFFSET keyInput
    mov ecx, SIZEOF keyInput - 1
    call ReadString

    cmp eax, 16
    jne InvalidKey


    ; =====================================================
    ; STEP 2 : ASCII HEX -> 8 BYTES
    ; =====================================================

    mov esi, OFFSET keyInput
    mov edi, OFFSET Key64

    call HexStringToBytes

    cmp eax, 0
    je InvalidKey


    ; =====================================================
    ; STEP 3 : PC-1
    ; =====================================================

    call GenerateC0D0


    ; =====================================================
    ; ตอนนี้
    ;
    ; C = C0
    ; D = D0
    ;
    ; =====================================================


    ; =====================================================
    ; STEP 4 : 16 ROUNDS
    ; =====================================================

    xor ebx, ebx


RoundLoop:

    cmp ebx, 16
    jge AllRoundsDone


    ; -----------------------------------------------------
    ; Shift schedule
    ; -----------------------------------------------------

    movzx ecx, BYTE PTR ShiftSchedule[ebx]


    ; -----------------------------------------------------
    ; C = ROL28(C, shift)
    ; -----------------------------------------------------

    mov eax, C
    call Rotate28
    mov C, eax


    ; -----------------------------------------------------
    ; D = ROL28(D, shift)
    ; -----------------------------------------------------

    mov eax, D
    call Rotate28
    mov D, eax


    ; -----------------------------------------------------
    ; หา address ของ SubKey
    ;
    ; round * 6
    ; -----------------------------------------------------

    mov eax, ebx
    imul eax, 6

    lea edi, SubKeys
    add edi, eax


    ; -----------------------------------------------------
    ; PC-2
    ; -----------------------------------------------------

    call GenerateSubKey


    inc ebx
    jmp RoundLoop


AllRoundsDone:

    mov edx, OFFSET msgOK
    call WriteString

    exit


InvalidKey:

    mov edx, OFFSET msgErr
    call WriteString

    exit

main ENDP


; =========================================================
; HexCharToValue
; =========================================================

HexCharToValue PROC

    push ebx

    cmp al, '0'
    jb CheckUpper

    cmp al, '9'
    ja CheckUpper

    sub al, '0'
    movzx eax, al

    pop ebx
    ret


CheckUpper:

    cmp al, 'A'
    jb CheckLower

    cmp al, 'F'
    ja CheckLower

    sub al, 'A'
    add al, 10

    movzx eax, al

    pop ebx
    ret


CheckLower:

    cmp al, 'a'
    jb InvalidHex

    cmp al, 'f'
    ja InvalidHex

    sub al, 'a'
    add al, 10

    movzx eax, al

    pop ebx
    ret


InvalidHex:

    mov eax, -1

    pop ebx
    ret

HexCharToValue ENDP


; =========================================================
; HexStringToBytes
; =========================================================

HexStringToBytes PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi
    push edi

    xor ecx, ecx


ConvertLoop:

    cmp ecx, 8
    jge ConvertDone


    ; high nibble
    mov al, [esi]
    call HexCharToValue

    cmp eax, -1
    je ConvertError

    mov ebx, eax

    shl ebx, 4


    ; low nibble
    mov al, [esi+1]
    call HexCharToValue

    cmp eax, -1
    je ConvertError

    or ebx, eax


    ; store byte
    mov [edi], bl

    inc edi
    add esi, 2
    inc ecx

    jmp ConvertLoop


ConvertDone:

    mov eax, 1
    jmp ConvertExit


ConvertError:

    xor eax, eax


ConvertExit:

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    pop ebp
    ret

HexStringToBytes ENDP


; =========================================================
; GetBit64
;
; ESI = Key64
; ECX = bit position 1-64
;
; EAX = bit
; =========================================================

GetBit64 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx

    mov eax, ecx
    dec eax

    ; byte index
    mov ebx, eax
    shr ebx, 3

    ; bit index
    and eax, 7

    ; shift = 7 - bit index
    mov edx, 7
    sub edx, eax

    mov cl, dl

    ; read byte
    movzx eax, BYTE PTR [esi+ebx]

    ; shift desired bit to bit 0
    shr eax, cl

    ; keep only bit 0
    and eax, 1


    pop edx
    pop ecx
    pop ebx

    pop ebp
    ret

GetBit64 ENDP


; =========================================================
; GenerateC0D0
;
; Key64 -> PC1 -> C0,D0
; =========================================================

GenerateC0D0 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov esi, OFFSET Key64

    xor edi, edi       ; C
    xor ebx, ebx       ; D
    xor edx, edx       ; PC1 index


PC1Loop:

    cmp edx, 56
    jge PC1Done

    movzx ecx, BYTE PTR PC1[edx]

    call GetBit64


    cmp edx, 28
    jl AddToC


    ; D
    shl ebx, 1
    or ebx, eax

    jmp PC1Next


AddToC:

    ; C
    shl edi, 1
    or edi, eax


PC1Next:

    inc edx
    jmp PC1Loop


PC1Done:

    mov C, edi
    mov D, ebx


    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    pop ebp
    ret

GenerateC0D0 ENDP


; =========================================================
; Rotate28
;
; EAX = 28-bit value
; ECX = shift count
;
; return EAX
; =========================================================

Rotate28 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx

    and eax, 0FFFFFFFh

    mov edx, ecx


RotateLoop:

    cmp edx, 0
    je RotateDone

    ; save MSB of 28-bit value
    mov ebx, eax
    shr ebx, 27

    ; left shift
    shl eax, 1

    ; keep only 28 bits
    and eax, 0FFFFFFFh

    ; circular bit
    or eax, ebx

    dec edx
    jmp RotateLoop


RotateDone:

    pop edx
    pop ecx
    pop ebx

    pop ebp
    ret

Rotate28 ENDP


; =========================================================
; GetBitCD
;
; ECX = position 1-56
; EAX = bit
; =========================================================

GetBitCD PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx

    cmp ecx, 28
    jg FromD


    ; -------------------------
    ; C
    ; -------------------------

    mov eax, C

    mov edx, 28
    sub edx, ecx

    mov cl, dl

    shr eax, cl
    and eax, 1

    jmp GetBitDone


FromD:

    ; -------------------------
    ; D
    ; -------------------------

    mov eax, D

    sub ecx, 28

    mov edx, 28
    sub edx, ecx

    mov cl, dl

    shr eax, cl
    and eax, 1


GetBitDone:

    pop edx
    pop ecx
    pop ebx

    pop ebp
    ret

GetBitCD ENDP


; =========================================================
; GenerateSubKey
;
; EDI = destination
;
; Generate 48-bit key using PC2
; =========================================================

GenerateSubKey PROC

    push ebp
    mov  ebp, esp

    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    xor ebx, ebx       ; current byte
    xor ecx, ecx       ; output byte index
    xor edx, edx       ; PC2 index


PC2Loop:

    cmp edx, 48
    jge PC2Done


    ; PC2[index]
    movzx eax, BYTE PTR PC2[edx]


    ; Save loop variables
    push edx
    push ecx

    ; GetBitCD input
    mov ecx, eax

    call GetBitCD

    pop ecx
    pop edx


    ; EAX = 0/1

    shl ebx, 1
    or ebx, eax

    inc edx


    ; every 8 bits
    mov eax, edx
    and eax, 7

    cmp eax, 0
    jne PC2Continue


    ; store byte
    mov BYTE PTR [edi+ecx], bl

    inc ecx

    xor ebx, ebx


PC2Continue:

    jmp PC2Loop


PC2Done:

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax

    pop ebp
    ret

GenerateSubKey ENDP


END main