@str = private constant [14 x i8] c"Hello, world\0A\00"
@msg = private constant [40 x i8] c"Program instructions disassembled: %d\n\00"
@add_msg = private constant [12 x i8] c"5 + 7 = %d\0A\00"

declare i32 @printf(i8*, ...)
declare i32 @test_capstone_program()

define i32 @main() {
entry:
    ; Print Hello World
    %str_ptr = getelementptr [14 x i8], [14 x i8]* @str, i32 0, i32 0
    %1 = call i32 (i8*, ...) @printf(i8* %str_ptr)

    ; Disassemble the program in memory
    %ins_count = call i32 @test_capstone_program()
    %msg_ptr = getelementptr [40 x i8], [40 x i8]* @msg, i32 0, i32 0
    %3 = call i32 (i8*, ...) @printf(i8* %msg_ptr, i32 %ins_count)

    ret i32 0
}
