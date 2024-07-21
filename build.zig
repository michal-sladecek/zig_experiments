const std = @import("std");
const builting = @import("builtin");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const project_name = b.option(
        []const u8,
        "project",
        "Project number",
    ) orelse "001";

    const main_path = try std.fmt.allocPrint(alloc, "src/{s}.zig", .{project_name});
    defer alloc.free(main_path);

    const seed = b.option(i64, "seed", "rng seed") orelse std.time.timestamp();
    const options = b.addOptions();
    options.addOption(i64, "seed", seed);

    const exe = b.addExecutable(.{
        .name = project_name,
        .root_source_file = b.path(main_path),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addOptions("config", options);
    exe.root_module.addImport("win32", b.createModule(.{ .root_source_file = b.path("lib/zigwin32/win32.zig") }));

    b.installArtifact(exe);

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    //
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path(main_path),
        .target = target,
        .optimize = optimize,
    });
    exe_unit_tests.root_module.addImport("win32", b.createModule(.{ .root_source_file = b.path("lib/zigwin32/win32.zig") }));

    exe_unit_tests.root_module.addOptions("config", options);
    b.installArtifact(exe_unit_tests);
}
