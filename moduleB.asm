TITLE Computer Organization and Assembly Language - Group Assignment 2026
INCLUDE Irvine32.inc

.386
.model flat, stdcall
.data
    ; permuted choice 1
         ; C0 first 28 bits
    PC_1 byte   57,49,41,33,25,17,9
         byte   1,58,50,42,34,26,18
         byte   10,2,59,51,43,35,27
         byte   19,11,3,60,52,44,36
         ; D0 last 28 bits
         byte   63,55,47,39,31,23,15
         byte   7,62,54,46,38,30,22
         byte   14,6,61,53,45,37,29
         byte   21,13,5,28,20,12,4
    ; permuted choice 2
    PC_2 byte   14,17,11,24,1,5
         byte   3,28,15 6,21,10
         byte   23,19,12,4,26,8
         byte   16,7,27,20,13,2
         byte   41,52,31,37,47,55
         byte   30,40,51,45,3348
         byte   44,49,39,56,34,53
         byte   46,42,50,36,29,32
    ; for shift
    SHIFT byte  1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
    ; for input KEYS (64 bits)
    KEYS_INPUT dword 32 DUP(0)
    ; for key64 after {doing something}
    KEYS_64 byte 8 DUP(0)
    ; for user input (temp only)
    USER_INPUT byte "Enter 64-bits DES Key:" ", 0
    MSG_OK byte "Key accepted.", 0Dh, 0Ah, 0
    MSG_ERROR byte "Invalid, Try again.", 0Dh, 0Ah, 0


    ; ---------------------------------------------------------------
    ; type something
    ; ---------------------------------------------------------------


.code

main PROC
    ; ---------------------------------------------------------------
    ; รับ input  key
    ; ---------------------------------------------------------------
     mov edx, OFFSET USER_INPUT
     call WriteString

     mov edx, OFFSET KEYS_INPUT
     mov ecx, SIZEOF KEYS_INPUT - 1
     call ReadString

     ; check 16 
     cmp eax, 16
     jne WrongKey

     ; hex to 8 byte
     mov esi, OFFSET KEYS_INPUT
     mov edi, OFFSET KEY_64

     call HexToByte

     cmp eax, 0
     je WrongKey

     mov edx, OFFSET MSG_OK
     call WriteString

     exit

WrongKey:
     mov edx, OFFSET KMSG_ERROR
     call WriteString

     exit

main ENDP

    ; ---------------------------------------------------------------
    ; description = change 12345678h to 12 34 56 78 
    ; ---------------------------------------------------------------
















































































HexToByte PROC
     
     push ebp 
     mov ebp, esp

     push ebx
     push ecx
     push edx
     push esi
     push edi

     xor ecx, ecx 

ConvertLoop: 

     cmp ecx, 8
     jge ConvertDone

     ; first digit
     mov al, [esi]
     call HexToValue

     cmp eax, -1
     je ConvertError

     mov ebx, eax

     shl ebx, 4

     ; second digit
     mov al, [esi + 1]
     call HexToValue

     cmp eax, -1
     je ConvertError

     or ebx, eax

     ; keep byte
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

HexToByte ENDP


     

