const std = @import("std");
const cve = @import("cve.zig");

/// ANSI styling, gated on stdout actually being a terminal so piped/redirected
/// output stays plain (same convention the original bash script used).
/// Shared by main.zig (pre-search status/summary lines) and ui.zig (the REPL
/// listing) so both render CVSS severity identically instead of drifting.
pub const Colors = struct {
    bold: []const u8 = "",
    dim: []const u8 = "",
    reset: []const u8 = "",
    red: []const u8 = "",
    bold_red: []const u8 = "",
    green: []const u8 = "",
    yellow: []const u8 = "",
    blue: []const u8 = "",
    cyan: []const u8 = "",

    pub const on: Colors = .{
        .bold = "\x1b[1m",
        .dim = "\x1b[2m",
        .reset = "\x1b[0m",
        .red = "\x1b[31m",
        .bold_red = "\x1b[1;31m",
        .green = "\x1b[32m",
        .yellow = "\x1b[33m",
        .blue = "\x1b[34m",
        .cyan = "\x1b[36m",
    };

    /// Severity -> color, per the requested 3-band scheme: critical/high
    /// both get the most-severe treatment (bold red), medium is yellow, low
    /// is blue. Unscored CVEs (`.none`) get a dim, unemphasized style rather
    /// than any severity color, since there's no score behind it.
    pub fn forSeverity(self: Colors, sev: cve.Severity) []const u8 {
        return switch (sev) {
            .critical, .high => self.bold_red,
            .medium => self.yellow,
            .low => self.blue,
            .none => self.dim,
        };
    }
};

pub fn stdoutIsTty(io: std.Io) bool {
    return std.Io.File.stdout().isTty(io) catch false;
}

pub fn detectColors(io: std.Io) Colors {
    if (!stdoutIsTty(io)) return .{};
    std.Io.File.stdout().enableAnsiEscapeCodes(io) catch {};
    return Colors.on;
}

/// Formats a CVSS score to one decimal place, or "n/a" when NVD hasn't
/// scored the CVE yet. `buf` must be at least 4 bytes ("10.0" is the longest
/// real score; "n/a" the longest fallback).
pub fn formatScore(score: ?f64, buf: []u8) ![]const u8 {
    if (score) |s| {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("{d:.1}", .{s});
        return w.buffered();
    }
    return "n/a";
}

test "formatScore renders one decimal place, and n/a for unscored CVEs" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("9.8", try formatScore(9.8, &buf));
    try std.testing.expectEqualStrings("10.0", try formatScore(10.0, &buf));
    try std.testing.expectEqualStrings("n/a", try formatScore(null, &buf));
}

test "Colors.forSeverity follows the 3-band scheme: bold red / yellow / blue" {
    const c = Colors.on;
    try std.testing.expectEqualStrings(c.bold_red, c.forSeverity(.critical));
    try std.testing.expectEqualStrings(c.bold_red, c.forSeverity(.high));
    try std.testing.expectEqualStrings(c.yellow, c.forSeverity(.medium));
    try std.testing.expectEqualStrings(c.blue, c.forSeverity(.low));
    try std.testing.expectEqualStrings(c.dim, c.forSeverity(.none));
}
