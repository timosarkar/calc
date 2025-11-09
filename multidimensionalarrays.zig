const std = @import("std");
const print = @import("std").debug.print;

pub fn main() void {
    const a: i32 = 1;
    print("hi {}\n", .{a});
}
