const std = @import("std");
const print = @import("std").debug.print; // import as
const testcase = @import("std").testing.expect;

// comments here
// there are no multiline comments lol

const a: i32 = 10; // integers
const b: f32 = 10.5; // floats
const c: bool = true; // bools
const d = null; // null values

var e: i32 = 10; // local vars
const testvar = 1234; // type inference supported

const mystring = "some string here";

pub fn main() void {
    std.debug.print("Hello, {s}!\n", .{"World"});
    print("len: {d}\n", .{mystring.len}); // string interpolation

    //const _: i32 = 12; // consts are immutable
    var myvar3: i32 = 13;
    myvar3 += 2;
}

pub fn arrays() void {
    const myarray = [_]u8{ "h", "e", "l", "l", "o" };
    return myarray;
}

pub fn square(myint: i32) i32 {
    return myint * myint;
}

// can be invoked using: zig test ./myfile.zig
test "name of the testcase here" {
    try testcase(square(2) == 4);
}
