const std = @import("std");
const builtin = @import("builtin");

pub const Os = enum {
    macos,
    linux,
    windows,
    other,
};

pub fn detectOs() Os {
    return switch (builtin.os.tag) {
        .macos => .macos,
        .linux => .linux,
        .windows => .windows,
        else => .other,
    };
}

pub fn label(os: Os) []const u8 {
    return switch (os) {
        .macos => "macOS",
        .linux => "Linux",
        .windows => "Windows",
        .other => "an unrecognized OS",
    };
}

/// `.none` means "no package-manager integration implemented for this OS
/// yet" (Linux/Windows in v1), not "this system has no package manager at
/// all" -- callers should fall back to printing a manual install URL rather
/// than assuming nothing can be done.
pub const PackageManager = enum {
    homebrew,
    none,

    pub fn label(self: PackageManager) []const u8 {
        return switch (self) {
            .homebrew => "Homebrew",
            .none => "none detected",
        };
    }
};

pub fn detectPackageManager(allocator: std.mem.Allocator, io: std.Io) PackageManager {
    return switch (detectOs()) {
        .macos => if (binExists(allocator, io, "brew")) .homebrew else .none,
        .linux, .windows, .other => .none,
    };
}

/// True if `bin` is runnable from PATH at all (regardless of exit code) --
/// distinguishes "not installed" (error.FileNotFound) from "installed but
/// this particular invocation failed for some other reason".
pub fn binExists(allocator: std.mem.Allocator, io: std.Io, bin: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ bin, "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch return false;
    return switch (result.term) {
        .exited => true,
        else => false,
    };
}

test "detectOs matches this build target" {
    // Sanity check only -- confirms the switch compiles and returns
    // something, not a specific value (that depends on where tests run).
    _ = detectOs();
}
