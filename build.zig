const std = @import("std");

pub fn build(builder: *std.Build) void {
    defer std.debug.print("Build finished...\n", .{});

    const exe = builder.addExecutable(.{
        .name = "shapr3d_hack",
        .link_libc = true,
        .root_source_file = .{ .path = "src/main.zig" },
        .optimize = .Debug,
        .target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .msvc,
        },
    });
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("user32");

    builder.installArtifact(exe);
}
