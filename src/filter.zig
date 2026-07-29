const std = @import("std");
const cve = @import("cve.zig");
const forge = @import("forge.zig");

/// Repos mentioning this many distinct CVE IDs (across description + readme)
/// are treated as list-of-everything aggregators (e.g. nomi-sec/PoC-in-GitHub
/// style repos) rather than a writeup for one specific vulnerability. The
/// common legit case -- a PoC that also references 2-3 related CVEs -- stays
/// well under this.
pub const default_threshold: usize = 8;

/// How many distinct CVE IDs appear across a hit's description + readme.
pub fn countCveMentions(allocator: std.mem.Allocator, description: []const u8, readme_full: []const u8) !usize {
    const combined = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ description, readme_full });
    defer allocator.free(combined);

    const mentions = try cve.scanUniqueDesc(allocator, combined);
    defer allocator.free(mentions);
    return mentions.len;
}

/// Sets cve_mention_count + is_dump on every hit in place. `threshold` is the
/// mention count at or above which a hit is flagged as a dump; 0 disables
/// dump detection entirely, matching the "0 means no limit" convention
/// `--max-cves`/`--max-hits` already use (taken literally, `count >= 0` would
/// instead flag *every* hit and hide the entire listing). Sorting,
/// hide/show-all, and the max-hits display cap are ui.zig's job (done
/// dynamically per render, since show-all is a live REPL toggle) -- this
/// only annotates.
pub fn annotate(allocator: std.mem.Allocator, hits: []forge.RepoHit, threshold: usize) !void {
    for (hits) |*hit| {
        const count = try countCveMentions(allocator, hit.description, hit.readme_full);
        hit.cve_mention_count = count;
        hit.is_dump = threshold != 0 and count >= threshold;
    }
}

test "annotate treats threshold 0 as disabled, not as flag-everything" {
    const allocator = std.testing.allocator;
    var hits = [_]forge.RepoHit{.{
        .host = .github,
        .owner = "someone",
        .name = "PoC",
        .full_name = "someone/PoC",
        .stars = 10,
        .description = "",
        .readme_excerpt = "",
        // Enough distinct CVEs to trip any sane threshold.
        .readme_full = "CVE-2024-4040 CVE-2024-1234 CVE-2023-9999 CVE-2023-8888 CVE-2023-7777 CVE-2023-6666 CVE-2023-5555 CVE-2023-4444 CVE-2023-3333",
    }};

    // Taken literally, `count >= 0` would flag this (and every other hit,
    // including zero-mention ones) and hide the whole listing.
    try annotate(allocator, &hits, 0);
    try std.testing.expect(!hits[0].is_dump);
    try std.testing.expectEqual(@as(usize, 9), hits[0].cve_mention_count);

    // A real threshold still flags it.
    try annotate(allocator, &hits, default_threshold);
    try std.testing.expect(hits[0].is_dump);
}

test "countCveMentions counts distinct CVEs across description and readme" {
    const allocator = std.testing.allocator;
    const n = try countCveMentions(allocator, "PoC for CVE-2023-22515", "See also CVE-2023-22515 and CVE-2021-44228.");
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "annotate flags a real-shaped CVE-list dump but keeps a focused writeup" {
    const allocator = std.testing.allocator;
    // Modeled on a real repo found during testing (getdrive/PoC): a running
    // list of unrelated CVEs in one repo, versus a focused single-CVE PoC
    // that happens to mention 2 related CVEs.
    var hits = [_]forge.RepoHit{
        .{
            .host = .github,
            .owner = "someone",
            .name = "PoC",
            .full_name = "someone/PoC",
            .stars = 10,
            .description = "PoC. Severity critical.",
            .readme_excerpt = "",
            .readme_full = "CVE-2024-4040 CVE-2024-1234 CVE-2023-9999 CVE-2023-8888 CVE-2023-7777 CVE-2023-6666 CVE-2023-5555 CVE-2023-4444 CVE-2023-3333",
        },
        .{
            .host = .github,
            .owner = "Chocapikk",
            .name = "CVE-2023-22515",
            .full_name = "Chocapikk/CVE-2023-22515",
            .stars = 154,
            .description = "Confluence Broken Access Control Exploit",
            .readme_excerpt = "",
            .readme_full = "Exploit for CVE-2023-22515, related to CVE-2023-22518.",
        },
    };

    try annotate(allocator, &hits, default_threshold);

    try std.testing.expect(hits[0].is_dump);
    try std.testing.expectEqual(@as(usize, 9), hits[0].cve_mention_count);

    try std.testing.expect(!hits[1].is_dump);
    try std.testing.expectEqual(@as(usize, 2), hits[1].cve_mention_count);
}
