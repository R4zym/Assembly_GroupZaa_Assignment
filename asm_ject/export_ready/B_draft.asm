TITLE Module B - DES Key Schedule Generator

; ============================================================
; Module B
; DES 16-Round Key Schedule Generator
;
; INPUT:
;   64-bit DES key = 8 bytes
;
; OUTPUT:
;   16 subkeys x 48 bits
;   Total = 96 bytes
;
; SubKey layout:
;   K1  = SubKeys + 0
;   K2  = SubKeys + 6
;   K3  = SubKeys + 12
;   ...
;   K16 = SubKeys + 90
;
; PUBLIC API:
;   GenerateKeySchedule
;
; Return:
;   EAX = 1  -> success
;   EAX = 0  -> failure
;
; ============================================================

.386
.model flat, stdcall

; ------------------------------------------------------------
; Public procedure
; ------------------------------------------------------------

PUBLIC GenerateKeySchedule

; ------------------------------------------------------------
; Include interface
; ------------------------------------------------------------

INCLUDE ModuleB.inc

; ============================================================
; DATA
; ============================================================

.data

; ------------------------------------------------------------
; DES Permuted Choice 1
;
; Input : 64-bit key
; Output: 56-bit key
;
; First 28 bits  -> C0
; Last  28 bits  -> D0
; ------------------------------------------------------------

PC1 BYTE \
    57,49,41,33,25,17, 9, 1,\
    58,50,42,34,26,18,10, 2,\
    59,51,43,35,27,19,11, 3,\
    60,52,44,36,63,55,47,39,\
    31,23,15, 7,62,54,46,38,\
    30,22,14, 6,61,53,45,37,\
    29,21,13, 5,28,20,12, 4


; ------------------------------------------------------------
; DES left-shift schedule
;
; Round:
;  1  -> 1
;  2  -> 1
;  3  -> 2
;  ...
; 16  -> 1
; ------------------------------------------------------------

ShiftSchedule BYTE \
    1,1,2,2,2,2,2,2,\
    1,2,2,2,2,2,2,1


; ------------------------------------------------------------
; DES Permuted Choice 2
;
; Cn + Dn (56 bits)
;        ↓
;       PC-2
;        ↓
; Kn (48 bits)
; ------------------------------------------------------------

PC2 BYTE \
    14,17,11,24, 1, 5,\
     3,28,15, 6,21,10,\
    23,19,12, 4,26, 8,\
    16, 7,27,20,13, 2,\
    41,52,31,37,47,55,\
    30,40,51,45,33,48,\
    44,49,39,56,34,53,\
    46,42,50,36,29,32


; ------------------------------------------------------------
; Working state
;
; These are internal to Module B.
; Module A/C does NOT need to access them.
; ------------------------------------------------------------

C_Val DWORD ?
D_Val DWORD ?


; ============================================================
; CODE
; ============================================================

.code


; ============================================================
; GenerateKeySchedule
;
; PUBLIC API
;
; Parameters:
;
;   [ebp+8]  = pointer to 8-byte DES key
;   [ebp+12] = pointer to 96-byte output buffer
;
; Output:
;
;   SubKeys:
;
;       +0   = K1
;       +6   = K2
;       +12  = K3
;       ...
;       +90  = K16
;
; Return:
;
;   EAX = 1 -> success
;   EAX = 0 -> failure
;
; Calling convention:
;
;   stdcall
;
; ============================================================

GenerateKeySchedule PROC

    push ebp
    mov  ebp, esp

    ; Save registers
    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; --------------------------------------------------------
    ; Get parameters
    ; --------------------------------------------------------

    mov esi, [ebp + 8]       ; pKey64
    mov edi, [ebp + 12]      ; pSubKeys

    ; --------------------------------------------------------
    ; Basic pointer validation
    ; --------------------------------------------------------

    test esi, esi
    jz KeyScheduleFail

    test edi, edi
    jz KeyScheduleFail


    ; --------------------------------------------------------
    ; Step 1:
    ;
    ; PC-1
    ;
    ; 64-bit Key
    ;      ↓
    ;    PC-1
    ;      ↓
    ;  C0 + D0
    ; --------------------------------------------------------

    push esi
    call GenerateC0D0


    ; --------------------------------------------------------
    ; Step 2:
    ;
    ; Generate K1-K16
    ; --------------------------------------------------------

    xor ebx, ebx             ; EBX = round index 0..15


KeyScheduleLoop:

    ; --------------------------------------------------------
    ; Check round
    ; --------------------------------------------------------

    cmp ebx, 16
    jge KeyScheduleDone


    ; --------------------------------------------------------
    ; Get shift amount
    ;
    ; ShiftSchedule[0..15]
    ; --------------------------------------------------------

    movzx ecx, BYTE PTR ShiftSchedule[ebx]


    ; --------------------------------------------------------
    ; Rotate C
    ; --------------------------------------------------------

    mov eax, C_Val

    push ecx
    push eax
    call Rotate28

    mov C_Val, eax


    ; --------------------------------------------------------
    ; Rotate D
    ; --------------------------------------------------------

    mov eax, D_Val

    push ecx
    push eax
    call Rotate28

    mov D_Val, eax


    ; --------------------------------------------------------
    ; Calculate destination:
    ;
    ; round * 6
    ;
    ; K1  -> +0
    ; K2  -> +6
    ; K3  -> +12
    ; ...
    ; K16 -> +90
    ; --------------------------------------------------------

    mov eax, ebx
    imul eax, 6

    lea edx, [edi + eax]


    ; --------------------------------------------------------
    ; PC-2
    ;
    ; Cn + Dn
    ;    ↓
    ;   PC-2
    ;    ↓
    ;  48-bit Kn
    ; --------------------------------------------------------

    push edx
    call GenerateSubKeyPC2


    ; --------------------------------------------------------
    ; Next round
    ; --------------------------------------------------------

    inc ebx
    jmp KeyScheduleLoop


; ============================================================
; SUCCESS
; ============================================================

KeyScheduleDone:

    mov eax, 1
    jmp KeyScheduleExit


; ============================================================
; FAILURE
; ============================================================

KeyScheduleFail:

    xor eax, eax


; ============================================================
; EXIT
; ============================================================

KeyScheduleExit:

    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    mov esp, ebp
    pop ebp

    ret 8

GenerateKeySchedule ENDP



; ============================================================
; GenerateC0D0
;
; Performs DES PC-1.
;
; Parameters:
;
;   [ebp+8] = pointer to 8-byte DES key
;
; Result:
;
;   C_Val = 28-bit C0
;   D_Val = 28-bit D0
;
; ============================================================

GenerateC0D0 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; --------------------------------------------------------
    ; Input key pointer
    ; --------------------------------------------------------

    mov esi, [ebp + 8]


    ; --------------------------------------------------------
    ; Clear accumulators
    ;
    ; EDI = C0
    ; EBX = D0
    ; EDX = PC1 index
    ; --------------------------------------------------------

    xor edi, edi
    xor ebx, ebx
    xor edx, edx


PC1_Loop:

    cmp edx, 56
    jge PC1_Done


    ; --------------------------------------------------------
    ; Get PC1 bit position
    ; --------------------------------------------------------

    movzx ecx, BYTE PTR PC1[edx]


    ; --------------------------------------------------------
    ; Get corresponding bit from original 64-bit key
    ;
    ; EAX = bit 0/1
    ; --------------------------------------------------------

    push ecx
    push esi
    call GetBit64


    ; --------------------------------------------------------
    ; First 28 bits -> C
    ; Remaining 28 bits -> D
    ; --------------------------------------------------------

    cmp edx, 28
    jge PC1_ToD


    ; --------------------------------------------------------
    ; C = (C << 1) | bit
    ; --------------------------------------------------------

    shl edi, 1
    or  edi, eax

    jmp PC1_Next


PC1_ToD:

    ; --------------------------------------------------------
    ; D = (D << 1) | bit
    ; --------------------------------------------------------

    shl ebx, 1
    or  ebx, eax


PC1_Next:

    inc edx
    jmp PC1_Loop


PC1_Done:

    ; --------------------------------------------------------
    ; Store C0 / D0
    ; --------------------------------------------------------

    mov C_Val, edi
    mov D_Val, ebx


    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    mov esp, ebp
    pop ebp

    ret 4

GenerateC0D0 ENDP



; ============================================================
; Rotate28
;
; Circular left rotation of a 28-bit value.
;
; Parameters:
;
;   [ebp+8]  = 28-bit value
;   [ebp+12] = shift amount (1 or 2)
;
; Return:
;
;   EAX = rotated 28-bit value
;
; ============================================================

Rotate28 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx


    ; --------------------------------------------------------
    ; Load value
    ; --------------------------------------------------------

    mov eax, [ebp + 8]

    ; Keep only 28 bits
    and eax, 0FFFFFFFh


    ; --------------------------------------------------------
    ; Shift count
    ; --------------------------------------------------------

    mov ecx, [ebp + 12]


RotateLoop:

    cmp ecx, 0
    jle RotateDone


    ; --------------------------------------------------------
    ; Save bit 27
    ;
    ; This bit will wrap around to bit 0.
    ; --------------------------------------------------------

    mov ebx, eax

    shr ebx, 27
    and ebx, 1


    ; --------------------------------------------------------
    ; Shift left
    ; --------------------------------------------------------

    shl eax, 1

    ; Keep only 28 bits
    and eax, 0FFFFFFFh


    ; --------------------------------------------------------
    ; Insert wrapped bit
    ; --------------------------------------------------------

    or eax, ebx


    dec ecx
    jmp RotateLoop


RotateDone:

    pop ecx
    pop ebx

    mov esp, ebp
    pop ebp

    ret 8

Rotate28 ENDP



; ============================================================
; GenerateSubKeyPC2
;
; Performs PC-2 using current C_Val / D_Val.
;
; Parameters:
;
;   [ebp+8] = destination pointer
;
; Output:
;
;   6 bytes = 48-bit subkey
;
; ============================================================

GenerateSubKeyPC2 PROC

    push ebp
    mov  ebp, esp

    push eax
    push ebx
    push ecx
    push edx
    push edi

    ; --------------------------------------------------------
    ; Destination
    ; --------------------------------------------------------

    mov edi, [ebp + 8]


    ; --------------------------------------------------------
    ; EBX = byte accumulator
    ; ECX = output byte index
    ; EDX = PC2 index
    ; --------------------------------------------------------

    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx


PC2_Loop:

    cmp edx, 48
    jge PC2_Done


    ; --------------------------------------------------------
    ; PC2[edx]
    ; --------------------------------------------------------

    movzx eax, BYTE PTR PC2[edx]


    ; --------------------------------------------------------
    ; Get bit from C/D
    ;
    ; EAX = 0 or 1
    ; --------------------------------------------------------

    push eax
    call GetBitCD


    ; --------------------------------------------------------
    ; Append bit:
    ;
    ; accumulator = accumulator << 1 | bit
    ; --------------------------------------------------------

    shl ebx, 1
    or  ebx, eax


    ; --------------------------------------------------------
    ; Next PC2 bit
    ; --------------------------------------------------------

    inc edx


    ; --------------------------------------------------------
    ; Every 8 bits -> store one byte
    ; --------------------------------------------------------

    mov eax, edx
    and eax, 7

    cmp eax, 0
    jne PC2_Loop


    ; --------------------------------------------------------
    ; Store byte
    ; --------------------------------------------------------

    mov BYTE PTR [edi + ecx], bl

    inc ecx

    xor ebx, ebx

    jmp PC2_Loop


PC2_Done:

    pop edi
    pop edx
    pop ecx
    pop ebx
    pop eax

    mov esp, ebp
    pop ebp

    ret 4

GenerateSubKeyPC2 ENDP



; ============================================================
; GetBitCD
;
; Gets one bit from current C/D state.
;
; Parameter:
;
;   [ebp+8] = position 1..56
;
; Return:
;
;   EAX = 0 or 1
;
; Mapping:
;
;   1..28 -> C
;   29..56 -> D
;
; ============================================================

GetBitCD PROC

    push ebp
    mov  ebp, esp

    push ecx
    push edx


    mov ecx, [ebp + 8]


    ; --------------------------------------------------------
    ; Position 1..28 -> C
    ; --------------------------------------------------------

    cmp ecx, 28
    jg ReadFromD


    mov eax, C_Val

    ; shift = 28 - position

    mov edx, 28
    sub edx, ecx

    mov cl, dl

    shr eax, cl
    and eax, 1

    jmp GetBitCD_Exit


ReadFromD:

    ; --------------------------------------------------------
    ; Position 29..56 -> D
    ; --------------------------------------------------------

    mov eax, D_Val

    ; Convert 29..56 -> 1..28

    sub ecx, 28

    ; shift = 28 - position

    mov edx, 28
    sub edx, ecx

    mov cl, dl

    shr eax, cl
    and eax, 1


GetBitCD_Exit:

    pop edx
    pop ecx

    mov esp, ebp
    pop ebp

    ret 4

GetBitCD ENDP



; ============================================================
; GetBit64
;
; Reads one bit from original 64-bit DES key.
;
; Parameters:
;
;   [ebp+8]  = pointer to 8-byte key
;   [ebp+12] = bit position 1..64
;
; Return:
;
;   EAX = 0 or 1
;
; DES bit ordering:
;
;   Byte 0 = bits 1..8
;   Byte 1 = bits 9..16
;   ...
;   Byte 7 = bits 57..64
;
; Within each byte:
;
;   bit 1 = MSB
;   bit 8 = LSB
;
; ============================================================

GetBit64 PROC

    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi


    ; --------------------------------------------------------
    ; Key pointer
    ; --------------------------------------------------------

    mov esi, [ebp + 8]


    ; --------------------------------------------------------
    ; Convert 1..64 -> 0..63
    ; --------------------------------------------------------

    mov eax, [ebp + 12]
    dec eax


    ; --------------------------------------------------------
    ; Byte index = bitIndex / 8
    ; --------------------------------------------------------

    mov ebx, eax
    shr ebx, 3


    ; --------------------------------------------------------
    ; Bit index inside byte = bitIndex % 8
    ; --------------------------------------------------------

    and eax, 7


    ; --------------------------------------------------------
    ; Load target byte
    ; --------------------------------------------------------

    movzx ecx, BYTE PTR [esi + ebx]


    ; --------------------------------------------------------
    ; Convert MSB-first position to shift count
    ;
    ; position 0 -> shift 7
    ; position 1 -> shift 6
    ; ...
    ; position 7 -> shift 0
    ; --------------------------------------------------------

    mov edx, 7
    sub edx, eax

    mov cl, dl


    ; --------------------------------------------------------
    ; Extract bit
    ; --------------------------------------------------------

    mov eax, 0

    movzx eax, BYTE PTR [esi + ebx]

    shr eax, cl
    and eax, 1


    pop esi
    pop edx
    pop ecx
    pop ebx

    mov esp, ebp
    pop ebp

    ret 8

GetBit64 ENDP


END