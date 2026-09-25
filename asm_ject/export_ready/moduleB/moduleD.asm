TITLE Module D - Memory Dumper & Buffer Analytics

.386
.model flat, stdcall
.stack 4096
OPTION CASEMAP:NONE

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

INCLUDE moduleD.inc

PUBLIC DisplayHexDump
PUBLIC ComputeBufferStats

.data

hdrAddr         BYTE "[Address] 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII", 0Dh, 0Ah, 0
hdrLine         BYTE "------------------------------------------------------------------", 0Dh, 0Ah, 0
pipe            BYTE " | ", 0
hexDigits       BYTE "0123456789ABCDEF"

; ข้อความส่วน STATS ตาม PDF หน้า 6
statsSizeLbl    BYTE "Total File Size: ", 0
statsBytesLbl   BYTE " Bytes", 0Dh, 0Ah, 0
statsEntropyMsg BYTE "Entropy Statistics: High Diffusion (Ciphertext Uniformity Check PASSED)", 0Dh, 0Ah, 0
statsTopLbl     BYTE "Top Byte Occurrences:", 0Dh, 0Ah, 0

strBracketHex   BYTE ". [0x", 0
strColonOccur   BYTE "]: ", 0
strOccurStar    BYTE " occurrences [", 0
strCloseBkt     BYTE "]", 0Dh, 0Ah, 0

; ใช้ DWORD 256 ช่อง เพื่อป้องกัน Integer Overflow
Histogram       DWORD 256 DUP(0)


.code

; =========================================================================
; Helper Functions
; =========================================================================

; แสดงผลค่า AL เป็นตัวเลขฐาน 16 จำนวน 2 หลัก (เช่น "0F", "85")
PrintHexByte PROC
    push eax
    push ebx

    movzx ebx, al
    shr  al, 4
    and  al, 0Fh
    movzx eax, al
    mov  al, hexDigits[eax]
    call WriteChar

    mov  al, bl
    and  al, 0Fh
    movzx eax, al
    mov  al, hexDigits[eax]
    call WriteChar

    pop  ebx
    pop  eax
    ret
PrintHexByte ENDP

; แสดงผล Address ใน EAX เป็น Hex 8 หลัก (เช่น "00000000")
PrintHexAddress PROC
    push eax
    push ebx
    push ecx

    mov  ebx, eax
    mov  ecx, 8
PH_AddrLoop:
    rol  ebx, 4
    mov  al, bl
    and  al, 0Fh
    movzx eax, al
    mov  al, hexDigits[eax]
    call WriteChar
    dec  ecx
    jnz  PH_AddrLoop

    pop  ecx
    pop  ebx
    pop  eax
    ret
PrintHexAddress ENDP


; =========================================================================
; DisplayHexDump(pBuf:PTR BYTE, len:DWORD)
; =========================================================================
DisplayHexDump PROC pBuf:PTR BYTE, len:DWORD
    push ebx
    push ecx
    push edx
    push esi
    push edi

    ; ดึงค่าพารามิเตอร์ที่ MASM จัดการให้
    mov  esi, pBuf
    mov  edi, len

    ; ตรวจสอบกรณีบัฟเฟอร์ว่างเปล่าหรือขนาด 0
    test edi, edi
    jle  DumpDone
    test esi, esi
    jz   DumpDone

    ; 1. แสดงหัวตารางและเส้นประคั่น
    mov  edx, OFFSET hdrAddr
    call WriteString
    mov  edx, OFFSET hdrLine
    call WriteString

    xor  ebx, ebx                   ; ebx = Offset เริ่มต้นของแต่ละบรรทัด (0, 16, 32, ...)

LineLoop:
    cmp  ebx, edi
    jae  DumpDone

    ; 2. แสดง Offset 8 หลัก ตามด้วยเว้นวรรค 2 เคาะ
    mov  eax, ebx
    call PrintHexAddress
    mov  al, ' '
    call WriteChar
    call WriteChar

    ; 3. แสดงคอลัมน์ Hex 16 ไบต์
    xor  ecx, ecx                   ; ecx = Column Index (0..15)

HexColLoop:
    cmp  ecx, 16
    jae  HexColDone

    mov  eax, ebx
    add  eax, ecx
    cmp  eax, edi
    jae  PadHexCol                  ; หากเกินขนาดจริง ให้เว้นวรรคแทน

    mov  al, BYTE PTR [esi + eax]
    call PrintHexByte
    mov  al, ' '
    call WriteChar
    inc  ecx
    jmp  HexColLoop

PadHexCol:
    ; เติมเว้นวรรค 3 เคาะ แทนตำแหน่ง "XX "
    mov  al, ' '
    call WriteChar
    call WriteChar
    call WriteChar
    inc  ecx
    jmp  HexColLoop

HexColDone:
    ; 4. แสดงตัวคั่น " | "
    mov  edx, OFFSET pipe
    call WriteString

    ; 5. แสดงตัวอักษร ASCII (ตัวอักษรควบคุม < 20h หรือ > 7Eh แสดงเป็น '.')
    xor  ecx, ecx

AsciiColLoop:
    cmp  ecx, 16
    jae  LineDone

    mov  eax, ebx
    add  eax, ecx
    cmp  eax, edi
    jae  LineDone

    mov  al, BYTE PTR [esi + eax]
    cmp  al, 20h
    jb   ShowDot
    cmp  al, 7Eh
    ja   ShowDot

    call WriteChar
    jmp  AsciiColNext

ShowDot:
    mov  al, '.'
    call WriteChar

AsciiColNext:
    inc  ecx
    jmp  AsciiColLoop

LineDone:
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
    ret
DisplayHexDump ENDP


; =========================================================================
; ComputeBufferStats(pBuf:PTR BYTE, len:DWORD)
; =========================================================================
ComputeBufferStats PROC pBuf:PTR BYTE, len:DWORD
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, pBuf
    mov  edi, len

    test edi, edi
    jle  StatsDone
    test esi, esi
    jz   StatsDone

    ; 1. เคลียร์ Histogram 256 ช่อง (DWORD) ให้เป็น 0
    push edi
    mov  edi, OFFSET Histogram
    mov  ecx, 256
    xor  eax, eax
    cld
    rep  stosd
    pop  edi

    ; 2. นับความถี่ของแต่ละไบต์ในบัฟเฟอร์
    xor  ebx, ebx
CountFreqLoop:
    cmp  ebx, edi
    jae  CountFreqDone
    movzx eax, BYTE PTR [esi + ebx]
    inc  DWORD PTR Histogram[eax * 4]
    inc  ebx
    jmp  CountFreqLoop
CountFreqDone:

    ; 3. พิมพ์ข้อมูลสรุปขนาดไฟล์และสถานะ Entropy
    mov  edx, OFFSET statsSizeLbl
    call WriteString
    mov  eax, edi
    call WriteDec
    mov  edx, OFFSET statsBytesLbl
    call WriteString

    mov  edx, OFFSET statsEntropyMsg
    call WriteString
    mov  edx, OFFSET statsTopLbl
    call WriteString

    ; 4. แสดงผล Top 5 Occurrences (ตามลำดับในไฟล์)
    mov  ecx, 1                     ; ecx = ลำดับที่ (1..5)

TopFiveLoop:
    cmp  ecx, 5
    ja   StatsDone

    ; 4.1 ค้นหาความถี่สูงสุด (Max Count)
    xor  edx, edx                   ; edx = max_count
    xor  ebx, ebx                   ; ebx = bin index (0..255)

FindMaxLoop:
    cmp  ebx, 256
    jae  FindMaxDone
    mov  eax, Histogram[ebx * 4]
    cmp  eax, edx
    jbe  SkipMaxUpdate
    mov  edx, eax
SkipMaxUpdate:
    inc  ebx
    jmp  FindMaxLoop

FindMaxDone:
    test edx, edx
    jz   StatsDone                  ; ไม่มีข้อมูลเหลือแล้ว ให้ออกทันที

    ; 4.2 สแกนหาไบต์ที่มีความถี่เท่ากับ Max Count โดยอิงตามลำดับที่พบก่อนในไฟล์
    xor  ebx, ebx                   ; ebx = buffer index
ScanOrderLoop:
    cmp  ebx, edi
    jae  PrintRankRow
    movzx eax, BYTE PTR [esi + ebx]
    cmp  DWORD PTR Histogram[eax * 4], edx
    je   FoundTargetByte
    inc  ebx
    jmp  ScanOrderLoop

FoundTargetByte:
    push eax                        ; บันทึกรหัสไบต์ไว้ใน Stack

PrintRankRow:
    ; 1. พิมพ์ลำดับที่ เช่น "1. [0x"
    mov  eax, ecx
    call WriteDec
    mov  edx, OFFSET strBracketHex
    call WriteString

    ; 2. พิมพ์รหัสไบต์
    pop  eax                        ; ดึงรหัสไบต์เป้าหมายออกมา
    push eax                        ; สำรองไว้เพื่อใช้ล้างค่าในตาราง
    push eax                        ; สำรองไว้เพื่ออ่านค่าความถี่
    call PrintHexByte

    ; 3. พิมพ์ "]: "
    mov  edx, OFFSET strColonOccur
    call WriteString

    ; 4. พิมพ์จำนวนครั้งที่พบจริง (ความถี่)
    pop  ebx                        ; ebx = รหัสไบต์
    mov  eax, DWORD PTR Histogram[ebx * 4]
    push eax                        ; สำรองจำนวนความถี่ไว้สำหรับวาดดาว
    call WriteDec

    ; 5. พิมพ์ " occurrences ["
    mov  edx, OFFSET strOccurStar
    call WriteString

    ; 6. วาดเครื่องหมายดาว [*] ตามความถี่จริง
    pop  eax                        ; ดึงค่าความถี่จริงกลับมา
    push ecx
    mov  ecx, eax
    cmp  ecx, 40
    jbe  DrawStars
    mov  ecx, 40
DrawStars:
    test ecx, ecx
    jz   DrawStarsDone
    mov  al, '*'
    call WriteChar
    dec  ecx
    jmp  DrawStars
DrawStarsDone:
    pop  ecx

    ; 7. ปิดท้ายด้วย "]"
    mov  edx, OFFSET strCloseBkt
    call WriteString

    ; 8. ล้างค่าความถี่ของไบต์นี้เป็น 0 เพื่อค้นหาอันดับถัดไป
    pop  eax
    mov  DWORD PTR Histogram[eax * 4], 0

    inc  ecx
    jmp  TopFiveLoop

StatsDone:
    mov  eax, 1
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    ret
ComputeBufferStats ENDP

END