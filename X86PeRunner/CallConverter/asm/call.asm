    EXPORT  |Stdcall|

	AREA .text,CODE,READONLY

|Stdcall|               ;R0:x86esp R1:Function Ptr
    push {r4-r11,lr}
    mov r4,r0           ; r4:x86_esp
    mov r5,r1           ; r5:func ptr
    str r0,[r4,#0]      ;arg0
    str r1,[r4,#4]      ;arg1
    str r2,[r4,#8]      ;arg2
    str r3,[r4,#12]     ;arg3
    push {r0,r1,r2,r3}  ;save these args,because the stack may be destroyed by ARM codes that we will BLX to
    mov r6,sp
    mov sp,r4
    add sp,16           ;remain x86 args
    blx r5
    ; now:r0(and may r1) got the return value
    mov sp,r6
    pop {r2,r3,r5,r6}
    ldr r2,[r4,#0]
    ldr r3,[r4,#4]
    ldr r5,[r4,#8]
    ldr r6,[R4,#12]
    pop {r4-r11,pc}

    
    END
