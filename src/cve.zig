const std = @import("std");

/// CVSS severity band, collapsed to the 3-color scheme bangbang displays:
/// critical/high both read as the most-severe color, medium and low each get
/// their own. `none` covers CVEs NVD hasn't scored yet (or a lookup that
/// failed) -- never a real CVSS band, just "no data".
pub const Severity = enum {
    critical,
    high,
    medium,
    low,
    none,

    pub fn fromNvdString(s: []const u8) Severity {
        if (std.ascii.eqlIgnoreCase(s, "CRITICAL")) return .critical;
        if (std.ascii.eqlIgnoreCase(s, "HIGH")) return .high;
        if (std.ascii.eqlIgnoreCase(s, "MEDIUM")) return .medium;
        if (std.ascii.eqlIgnoreCase(s, "LOW")) return .low;
        return .none;
    }

    /// Ordering for "which of these severities is worse" -- higher is more
    /// severe. Used to pick the most-severe entry out of a list of CVEs.
    pub fn rank(self: Severity) u8 {
        return switch (self) {
            .critical => 4,
            .high => 3,
            .medium => 2,
            .low => 1,
            .none => 0,
        };
    }
};

/// A CVE's headline CVSS score/severity, picked from whichever metric
/// version NVD published (see nvd.zig's extraction priority). `score` is
/// null when NVD hasn't analyzed/scored the CVE yet.
pub const Cvss = struct {
    score: ?f64 = null,
    severity: Severity = .none,
};

/// A parsed CVE identifier: CVE-<year>-<sequence>. `sequence` is stored as a
/// plain integer; canonical rendering zero-pads it back to a 4-digit minimum
/// (the CVE ID syntax rule), e.g. year=2023 sequence=67 -> "CVE-2023-0067".
pub const CveId = struct {
    year: u16,
    sequence: u32,

    pub fn order(a: CveId, b: CveId) std.math.Order {
        if (a.year != b.year) return std.math.order(a.year, b.year);
        return std.math.order(a.sequence, b.sequence);
    }

    pub fn eql(a: CveId, b: CveId) bool {
        return a.year == b.year and a.sequence == b.sequence;
    }

    pub fn print(self: CveId, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.print("CVE-{d}-{d:0>4}", .{ self.year, self.sequence });
    }

    /// Renders into `buf` and returns the written slice. `buf` must be large
    /// enough ("CVE-" + 4 + "-" + up to 7 digits = 16 bytes covers every
    /// value the parser accepts).
    pub fn toSlice(self: CveId, buf: []u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try self.print(&w);
        return w.buffered();
    }

    /// Same, but heap-allocated -- for callers that need the string to
    /// outlive a stack buffer (e.g. stored in a longer-lived struct field).
    pub fn allocString(self: CveId, allocator: std.mem.Allocator) ![]const u8 {
        var buf: [16]u8 = undefined;
        return allocator.dupe(u8, try self.toSlice(&buf));
    }
};

/// Everything after a case-confirmed "cve-" prefix: 4 digit year, '-', then
/// 4-7 digit sequence. Returns the parsed id plus how many bytes of `rest`
/// were consumed, or null if the grammar doesn't match at the start of `rest`.
fn parseYearAndSeq(rest: []const u8) ?struct { cve: CveId, len: usize } {
    if (rest.len < 4) return null;
    for (rest[0..4]) |c| {
        if (!std.ascii.isDigit(c)) return null;
    }
    const year = std.fmt.parseInt(u16, rest[0..4], 10) catch return null;
    if (rest.len < 5 or rest[4] != '-') return null;

    var seq_len: usize = 0;
    while (seq_len < 7 and 5 + seq_len < rest.len and std.ascii.isDigit(rest[5 + seq_len])) : (seq_len += 1) {}
    if (seq_len < 4) return null; // CVE sequence numbers are always >= 4 digits

    const seq = std.fmt.parseInt(u32, rest[5 .. 5 + seq_len], 10) catch return null;
    return .{ .cve = .{ .year = year, .sequence = seq }, .len = 4 + 1 + seq_len };
}

/// Parses `s` as exactly one CVE ID (case-insensitive "CVE-" prefix), with no
/// leading/trailing garbage. Use for validating a whole command-line argument.
pub fn parseExact(s: []const u8) ?CveId {
    if (s.len < 4 or !std.ascii.eqlIgnoreCase(s[0..4], "cve-")) return null;
    const m = parseYearAndSeq(s[4..]) orelse return null;
    if (4 + m.len != s.len) return null;
    return m.cve;
}

/// Scans arbitrary free text (a README, a description) for every CVE-ID-shaped
/// substring and returns the deduped set, sorted newest-first. Used both to
/// pull CVE IDs out of NVD-adjacent text and to count "how many distinct CVEs
/// does this repo mention" for the dump-repo filter.
pub fn scanUniqueDesc(allocator: std.mem.Allocator, text: []const u8) ![]CveId {
    var found: std.ArrayList(CveId) = .empty;
    defer found.deinit(allocator);

    var i: usize = 0;
    while (i + 4 <= text.len) {
        if (std.ascii.eqlIgnoreCase(text[i .. i + 4], "cve-")) {
            if (parseYearAndSeq(text[i + 4 ..])) |m| {
                try found.append(allocator, m.cve);
                i += 4 + m.len;
                continue;
            }
        }
        i += 1;
    }

    return dedupSortedDesc(allocator, found.items);
}

fn lessThanDesc(_: void, a: CveId, b: CveId) bool {
    return a.order(b) == .gt;
}

/// Returns a newly allocated, deduped copy of `items` sorted newest-first.
pub fn dedupSortedDesc(allocator: std.mem.Allocator, items: []const CveId) ![]CveId {
    const buf = try allocator.dupe(CveId, items);
    std.sort.pdq(CveId, buf, {}, lessThanDesc);

    if (buf.len == 0) return buf;
    var w: usize = 1;
    for (buf[1..]) |item| {
        if (!item.eql(buf[w - 1])) {
            buf[w] = item;
            w += 1;
        }
    }
    // Must actually shrink the allocation (not just return a subslice) so the
    // result is independently freeable with the debug allocator's size tracking.
    if (w == buf.len) return buf;
    return try allocator.realloc(buf, w);
}

test "parseExact accepts canonical and lowercase forms, rejects garbage" {
    try std.testing.expectEqual(CveId{ .year = 2023, .sequence = 22515 }, parseExact("CVE-2023-22515").?);
    try std.testing.expectEqual(CveId{ .year = 2021, .sequence = 44228 }, parseExact("cve-2021-44228").?);
    try std.testing.expectEqual(@as(?CveId, null), parseExact("CVE-2023-1")); // too few digits
    try std.testing.expectEqual(@as(?CveId, null), parseExact("CVE-2023-22515-extra"));
    try std.testing.expectEqual(@as(?CveId, null), parseExact("not-a-cve"));
}

test "toSlice zero-pads sequence to a 4-digit minimum" {
    var buf: [16]u8 = undefined;
    const s = (CveId{ .year = 2023, .sequence = 67 }).toSlice(&buf) catch unreachable;
    try std.testing.expectEqualStrings("CVE-2023-0067", s);
}

test "dedupSortedDesc fixes the lexicographic-sort bug: numeric order, not string order" {
    const allocator = std.testing.allocator;
    const input = [_]CveId{
        .{ .year = 2023, .sequence = 9999 },
        .{ .year = 2023, .sequence = 10000 },
        .{ .year = 2024, .sequence = 1 },
        .{ .year = 2021, .sequence = 44228 },
        .{ .year = 2023, .sequence = 9999 }, // duplicate
    };
    const out = try dedupSortedDesc(allocator, &input);
    defer allocator.free(out);

    try std.testing.expectEqual(@as(usize, 4), out.len);
    try std.testing.expectEqual(CveId{ .year = 2024, .sequence = 1 }, out[0]);
    try std.testing.expectEqual(CveId{ .year = 2023, .sequence = 10000 }, out[1]); // > 9999, must sort first
    try std.testing.expectEqual(CveId{ .year = 2023, .sequence = 9999 }, out[2]);
    try std.testing.expectEqual(CveId{ .year = 2021, .sequence = 44228 }, out[3]);
}

test "Severity.fromNvdString maps NVD's band strings, case-insensitively, and defaults unknowns to none" {
    try std.testing.expectEqual(Severity.critical, Severity.fromNvdString("CRITICAL"));
    try std.testing.expectEqual(Severity.high, Severity.fromNvdString("High"));
    try std.testing.expectEqual(Severity.medium, Severity.fromNvdString("medium"));
    try std.testing.expectEqual(Severity.low, Severity.fromNvdString("LOW"));
    try std.testing.expectEqual(Severity.none, Severity.fromNvdString(""));
    try std.testing.expectEqual(Severity.none, Severity.fromNvdString("NONE"));
    try std.testing.expectEqual(Severity.none, Severity.fromNvdString("garbage"));
}

test "Severity.rank orders critical > high > medium > low > none" {
    try std.testing.expect(Severity.critical.rank() > Severity.high.rank());
    try std.testing.expect(Severity.high.rank() > Severity.medium.rank());
    try std.testing.expect(Severity.medium.rank() > Severity.low.rank());
    try std.testing.expect(Severity.low.rank() > Severity.none.rank());
}

test "scanUniqueDesc finds every mention, case-insensitively, deduped" {
    const allocator = std.testing.allocator;
    const text = "Related: cve-2023-22515 and CVE-2023-22515 also see CVE-2021-44228.";
    const out = try scanUniqueDesc(allocator, text);
    defer allocator.free(out);

    try std.testing.expectEqual(@as(usize, 2), out.len);
    try std.testing.expectEqual(CveId{ .year = 2023, .sequence = 22515 }, out[0]);
    try std.testing.expectEqual(CveId{ .year = 2021, .sequence = 44228 }, out[1]);
}
