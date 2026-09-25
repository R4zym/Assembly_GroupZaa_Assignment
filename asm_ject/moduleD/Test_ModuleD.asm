TITLE Test Module D

.386
.model flat, stdcall
.stack 4096

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib



.data

testBuf BYTE 01h,23h,45h,67h,89h,0ABh,0CDh,0EFh,\
            01h,23h,45h,67h,89h,0ABh,0CDh,0EFh
testLen DWORD 16

hdrAddr BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  | ASCII", 0Dh,0Ah,0
hdrLine BYTE "------------------------------------------------------------------", 0Dh,0Ah,0
pad3    BYTE "   ", 0
pipe    BYTE " | ", 0


.code

; print AL as 2 hex digits
PrintHexByte PROC
    push eax
    push ebx

    mov  bl, al

    shr  al, 4
    cmp  al, 9
    jbe  DigitUpper
    add  al, 'A' - 10
    jmp  PrintUpper
DigitUpper:
    add  al, '0'
PrintUpper:
    call WriteChar

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


; DisplayHexDump(pBuf, len)
DisplayHexDump PROC
    push ebp
    mov  ebp, esp

    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, [ebp+8]
    mov  edi, [ebp+12]

    mov  edx, OFFSET hdrAddr
    call WriteString
    mov  edx, OFFSET hdrLine
    call WriteString

    xor  ebx, ebx

LineLoop:
    cmp  ebx, edi
    jge  DumpDone

    mov  eax, ebx
    call WriteHex

    mov  edx, OFFSET pad3
    call WriteString

    xor  ecx, ecx
ByteLoop:
    cmp  ecx, 16
    jge  ByteLoopDone

    mov  eax, ebx
    add  eax, ecx
    cmp  eax, edi
    jge  PadByte

    mov  al, BYTE PTR [esi + eax]
    call PrintHexByte
    mov  al, ' '
    call WriteChar

    inc  ecx
    jmp  ByteLoop

PadByte:
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar
    mov  al, ' '
    call WriteChar

    inc  ecx
    jmp  ByteLoop

ByteLoopDone:
    mov  edx, OFFSET pipe
    call WriteString

    xor  ecx, ecx
AsciiLoop:
    cmp  ecx, 16
    jge  AsciiDone

    mov  eax, ebx
    add  eax, ecx
    cmp  eax, edi
    jge  AsciiDone

    mov  al, BYTE PTR [esi + eax]
    cmp  al, 20h
    jb   NotPrintable
    cmp  al, 7Eh
    ja   NotPrintable

    call WriteChar
    jmp  AsciiNext

NotPrintable:
    mov  al, '.'
    call WriteChar

AsciiNext:
    inc  ecx
    jmp  AsciiLoop

AsciiDone:
    call Crlf
    add  ebx, 16
    jmp  LineLoop

DumpDone:
    mov  eax, 1

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx

    mov  esp, ebp
    pop  ebp
    ret  8
DisplayHexDump ENDP


; ComputeBufferStats(pBuf, len)
ComputeBufferStats PROC
    push ebp
    mov  ebp, esp

    ; TODO

    mov  eax, 1

    mov  esp, ebp
    pop  ebp
    ret  8
ComputeBufferStats ENDP


main PROC
    push testLen
    push OFFSET testBuf
    call DisplayHexDump

    call Crlf
    call WaitMsg

    exit
main ENDP

END main
