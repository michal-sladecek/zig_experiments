const std = @import("std");
const config = @import("config");
const win32 = @import("win32");
const RndGen = std.Random.DefaultPrng;

const HINSTANCE = std.os.windows.HINSTANCE;

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    Reserved1: [2]std.os.windows.PVOID,
    InMemoryOrderLinks: std.os.windows.LIST_ENTRY,
    Reserved2: [2]std.os.windows.PVOID,
    DllBase: std.os.windows.PVOID,
    EntryPoint: std.os.windows.PVOID,
    SizeOfImage: std.os.windows.ULONG,
    FullDllName: std.os.windows.UNICODE_STRING,
    BaseDllName: std.os.windows.UNICODE_STRING,
    Reserved5: [3]std.os.windows.PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: std.os.windows.ULONG,
        Reserved6: std.os.windows.PVOID,
    },
    TimeDateStamp: std.os.windows.ULONG,
};

fn getModuleHandleHash(comptime moduleName: []const u8) !?HINSTANCE {
    const moduleHash = comptime hashString(moduleName);
    const peb = std.os.windows.peb();

    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer.?[0..mod_name_length]);
        if (hashString(mod_name_utf8) == moduleHash) {
            return @ptrCast(loaded_module.DllBase);
        }
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
    return null;
}

fn getComptimeRandomNumber(comptime local_seed: comptime_int) comptime_int {
    comptime var rnd = RndGen.init(@as(u64, @bitCast(local_seed ^ config.seed)));
    return rnd.next();
}
// We use djb2 function
fn hashString(s: []const u8) u64 {
    var hash: u64 = getComptimeRandomNumber(1);
    for (s) |c| {
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(c))[0];
    }
    return hash;
}
test "getModuleHandleHash kernel32.dll" {
    std.debug.print("Hash of kernel32.dll: 0x{x}\n", .{hashString("kernel32.dll")});
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("kernel32.dll").?, (try getModuleHandleHash("kernel32.dll")).?);
}
test "getModuleHandleHash ntdll.dll" {
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("ntdll.dll").?, (try getModuleHandleHash("ntdll.dll")).?);
}
test "getModuleHandleHash nonexistent dll" {
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("notexistent.dll"), try getModuleHandleHash("nosuchdll.dll"));
    try std.testing.expectEqual(null, try getModuleHandleHash("nosuchdll.dll"));
}

pub fn main() !void {
    std.debug.print("{} {} {}\n", .{ getComptimeRandomNumber(1), getComptimeRandomNumber(2), getComptimeRandomNumber(3) });
    const ptr: *anyopaque = @ptrCast((try getModuleHandleHash("kernel32.dll")).?);
    std.debug.print("{}\n", .{ptr});
}
