declare i32 @printf(i8*, ...)
declare i32 @disasm_function(i8*, i32)

define i32 @main() {
entry:
    ; Disassemble main
    %func_ptr = bitcast i32 ()* @main to i8*
    %ins_count = call i32 @disasm_function(i8* %func_ptr, i32 128)
    ret i32 0
}
