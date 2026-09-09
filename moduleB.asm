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
    SHIFT byte  1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,,1
    ; for input KEYS (64 bits)
     




.code
