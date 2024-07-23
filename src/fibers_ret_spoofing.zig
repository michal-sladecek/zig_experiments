const std = @import("std");
const win32 = @import("win32").everything;

var main_fiber: *anyopaque = undefined;

fn fiberSpoofRet(parameters: [*]u64) void {
    // We support only 6 args, easy to add more if one wants
    const func_addr = parameters[0];
    // Just the x64 windows calling convention
    // https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame
    const rcx = parameters[1];
    const rdx = parameters[2];
    const r8 = parameters[3];
    const r9 = parameters[4];
    const stack1 = parameters[5];
    const stack2 = parameters[6];
    _ = asm volatile (
        \\ pushq %[stack2]
        \\ pushq %[stack1]
        \\ pushq %r9
        \\ pushq %r8
        \\ pushq %rdx
        \\ pushq %rcx
        \\ pushq $0
        \\ jmp *%rbx
        : [ret] "={rax}" (-> usize),
        : [_] "{rbx}" (func_addr),
          [_] "{rcx}" (rcx),
          [_] "{rdx}" (rdx),
          [_] "{r8}" (r8),
          [_] "{r9}" (r9),
          [stack1] "r" (stack1),
          [stack2] "r" (stack2),
        : "rbx"
    );
}
// Return value is global so it can be set from vectored exception handler
var return_value: u64 = undefined;

fn vectoredExceptionHandler(exception_pointers: *win32.EXCEPTION_POINTERS) void {
    const context = exception_pointers.ContextRecord.?;
    // We take the Rax - return value according to x64 calling conv
    // This will not work in Debug mode - Zig's debug mode handles exception and will cause context to be different
    return_value = context.Rax;
    // We switch back to the calling fiber
    win32.SwitchToFiber(main_fiber);
}

fn callFunctionWithSpoofedRet(function_ptr: *const anyopaque, arguments: anytype) u64 {
    // We setup the VEH, and also make it remove on function return
    const veh_method_ptr: win32.PVECTORED_EXCEPTION_HANDLER = @ptrCast(&vectoredExceptionHandler);
    const veh = win32.AddVectoredExceptionHandler(0, veh_method_ptr);
    defer _ = win32.RemoveVectoredExceptionHandler(veh);

    // 7 is enough for demonstration
    var parameters: [7]u64 = undefined;
    // Param 1 is the function we want to call
    parameters[0] = @intFromPtr(function_ptr);
    // All other params are arguments to the function
    inline for (std.meta.fields(@TypeOf(arguments)), 1..) |field, idx| {
        const value: u64 = @field(arguments, field.name);
        parameters[idx] = value;
    }

    const fiber_method_ptr: win32.LPFIBER_START_ROUTINE = @ptrCast(&fiberSpoofRet);
    const fiber_ptr = win32.CreateFiber(0, fiber_method_ptr, @ptrCast(&parameters)).?;
    main_fiber = win32.ConvertThreadToFiber(null).?;
    // Stuff happens here
    // 1. Execution is given to the fiber with entrypoint of fiberSpoofRet
    // 2. The wanted function is called
    // 3. Return to 0x0 causes excaption and VEH is invoked
    // 4. VEH saves the return value and exits the fiber
    win32.SwitchToFiber(fiber_ptr);
    // 5. Execution is seamelessly returned here
    _ = win32.ConvertFiberToThread();
    // 6. We return the value
    return return_value;
}

// The testing function we will call.
// The function returns 0xbeef if the arguments were passed correctly
// and the return address was spoofed
// This helps us test
fn spoofedRetTestHelper(i: u64, j: u64, k: u64, l: u64, m: u64) u64 {
    const ret = @returnAddress();
    std.debug.print("Args: {x},{x},{x},{x},{x}\n", .{ i, j, k, l, m });
    std.debug.print("Return address: 0x{x}\n", .{ret});
    if (ret == 0 and i == 0xaaaa and j == 0xbbbb and k == 0xcccc and l == 0xdddd and m == 0xeeee) {
        return 0xbeef;
    }
    return 0;
}

test "spoofing works correctly" {
    const returned_value = callFunctionWithSpoofedRet(@ptrCast(&spoofedRetTestHelper), .{ 0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee });
    try std.testing.expectEqual(0xbeef, returned_value);
}
pub fn main() !void {
    std.debug.print("Hello from main\n", .{});

    const HKEY_CURRENT_USER = win32.HKEY_CURRENT_USER;

    var opened_reg: ?win32.HKEY = undefined;
    _ = win32.RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE", @ptrCast(&opened_reg));
    _ = callFunctionWithSpoofedRet(@ptrCast(&win32.RegOpenKeyA), .{ @intFromPtr(HKEY_CURRENT_USER), @intFromPtr("System"), @intFromPtr(&opened_reg) });
}
