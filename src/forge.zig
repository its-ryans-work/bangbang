const std = @import("std");
const cve = @import("cve.zig");

/// Shared shapes produced by github.zig/gitlab.zig, annotated+filtered by
/// filter.zig, and displayed by ui.zig. Everything here is expected to be
/// allocated from a single arena that outlives one whole tool invocation —
/// nothing in this module frees its own string fields.
pub const Host = enum {
    github,
    gitlab,
    codeberg,
    exploitdb,

    pub fn label(self: Host) []const u8 {
        return switch (self) {
            .github => "gh",
            .gitlab => "glab",
            .codeberg => "cb",
            .exploitdb => "edb",
        };
    }

    /// Whether this host publishes a star count worth filtering on.
    ///
    /// exploit-db is a flat archive of submitted exploits with no popularity
    /// signal at all -- its hits always carry `stars = 0`. Treating that as
    /// "zero stars" would make `--min-stars 1` silently delete every
    /// exploit-db result, so the star threshold only applies to the three
    /// forges that actually have one.
    pub fn hasStars(self: Host) bool {
        return switch (self) {
            .github, .gitlab, .codeberg => true,
            .exploitdb => false,
        };
    }

    /// Parses a `--sources` token, accepting either the short label used
    /// elsewhere in the UI ("gh") or the full host name ("github").
    pub fn fromLabel(s: []const u8) ?Host {
        if (std.mem.eql(u8, s, "gh") or std.mem.eql(u8, s, "github")) return .github;
        if (std.mem.eql(u8, s, "glab") or std.mem.eql(u8, s, "gitlab")) return .gitlab;
        if (std.mem.eql(u8, s, "cb") or std.mem.eql(u8, s, "codeberg")) return .codeberg;
        if (std.mem.eql(u8, s, "edb") or std.mem.eql(u8, s, "exploitdb")) return .exploitdb;
        return null;
    }
};

pub const RepoHit = struct {
    host: Host,
    owner: []const u8,
    name: []const u8,
    full_name: []const u8, // "owner/name", what gh/glab/git expect for clone
    stars: u32,
    description: []const u8, // possibly empty, never null
    readme_excerpt: []const u8, // short, badge-stripped, for the collapsed view
    readme_full: []const u8, // fuller text, shown on `expand`
    cve_mention_count: usize = 0, // set by filter.zig
    is_dump: bool = false, // set by filter.zig once cve_mention_count is known

    // Legitimacy signals the user can eyeball directly in the listing:
    // fork count, repo age (a PoC created the same week as the CVE is a much
    // stronger signal than one created years earlier/later), and links to
    // click through for more.
    forks: u32 = 0,
    created_at: []const u8 = "", // "" if unknown; date-only, e.g. "2023-10-10"
    repo_url: []const u8 = "",
    owner_url: []const u8 = "",

    // GitLab-only: carries what fetchReadme needs from the search response
    // through to the readme-fetch step (GitLab has no GitHub-style
    // auto-resolving readme endpoint, so the exact path + branch found at
    // search time has to travel with the hit). Empty/unused for GitHub hits.
    gitlab_default_branch: []const u8 = "",
    gitlab_readme_path: []const u8 = "", // "" means no readme found in search response

    // ExploitDB-only: the CSV's `file` column (e.g.
    // "exploits/linux/remote/52622.py") -- both the raw-file path for
    // fetchReadme/download and the source of the on-disk filename when
    // downloaded. Empty/unused for every other host.
    exploitdb_file: []const u8 = "",
};

/// One CVE (or, for the zero-hits fallback search, a synthetic
/// non-CVE-specific query) plus the hits found for it, ready to hand to the
/// REPL. `display_label`/`dir_name` are computed once at build time rather
/// than requiring every consumer to know how to format a CveId (or a
/// fallback query) themselves.
pub const CveGroup = struct {
    display_label: []const u8, // shown in the listing, e.g. "CVE-2023-22515" or "\"confluence\" CVE (generic search)"
    dir_name: []const u8, // filesystem-safe, used for the download directory name
    hits: []RepoHit,
    hidden_dump_count: usize = 0, // hits that were filtered out as CVE-list dumps
    cvss: cve.Cvss = .{}, // .none/null for the generic-fallback-search group, which isn't tied to one CVE
    rate_limited: std.EnumSet(Host) = .initEmpty(), // which hosts (if any) hit a rate limit while building this group
};

/// Return shape for a single host's `search`/`searchCve` call: the hits
/// found (possibly empty), plus whether *this specific call* looked
/// rate-limited -- distinct from "genuinely zero repos matched" so callers
/// can warn the user their results may be incomplete instead of silently
/// reporting a clean zero.
pub const SearchResult = struct {
    hits: []RepoHit,
    rate_limited: bool = false,
};

/// Case-insensitive substring search -- std has no built-in for this. Shared
/// by looksRateLimited below and exploitdb.zig's keyword search.
pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

/// Best-effort rate-limit detection shared by all 3 hosts. A 403 or 429
/// status is the strongest signal and is only available in HTTP mode
/// (confirmed against GitHub's and GitLab's own docs: GitHub uses 403 for
/// its primary limit and 403/429 for the secondary/abuse limit; GitLab uses
/// 429 specifically -- distinct from the 500 gitlab.com already returns for
/// a genuinely empty search, so this can't misfire on that). CLI-mode calls
/// (gh/glab api subprocesses) don't expose a raw HTTP status, so this also
/// falls back to scanning the body text both APIs are documented to use.
pub fn looksRateLimited(status: ?std.http.Status, body: []const u8) bool {
    if (status) |s| {
        if (s == .forbidden or s == .too_many_requests) return true;
    }
    return containsIgnoreCase(body, "rate limit") or containsIgnoreCase(body, "too many requests");
}

/// Replaces anything that isn't alphanumeric/-/_ with '-', for building a
/// filesystem-safe directory name out of arbitrary user-supplied text (the
/// zero-hits fallback search's keyword).
pub fn sanitizeDirName(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        out[i] = if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_') c else '-';
    }
    return out;
}

/// Like `sanitizeDirName` but keeps '.' so ordinary repo names (`foo.js`,
/// `poc.py`) survive intact, while still guaranteeing the result is a single
/// harmless path component.
///
/// Everything reaching here is remote-controlled: a repo owner/name from a
/// forge API, or an id straight out of exploit-db's CSV. A component
/// containing a separator or a `..` would let a download escape its
/// destination directory once joined into a path, so separators become '-'
/// and any dot that would start a component or continue a run of dots
/// (i.e. `.` / `..` / leading-dot hidden names) is defused the same way.
/// Empty input yields "unnamed" rather than an empty path segment. Always
/// returns freshly allocated memory (never a borrowed literal), so callers
/// can free the result unconditionally.
pub fn sanitizePathComponent(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (s.len == 0) return allocator.dupe(u8, "unnamed");
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        out[i] = if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') c else '-';
    }
    for (out, 0..) |c, i| {
        if (c == '.' and (i == 0 or out[i - 1] == '.')) out[i] = '-';
    }
    return out;
}

/// Writes remote-controlled text with terminal control bytes stripped.
///
/// Repo descriptions and README bodies are authored by whoever published the
/// repo -- exactly the strangers this tool exists to surface -- and get
/// printed straight to the user's terminal. Left raw, an embedded escape
/// sequence could rewrite the listing to forge the very trust signals
/// (stars, age, the dump-flagged marker) the user is reading it for, or hit
/// terminals that honor OSC 52 clipboard writes. bangbang's own coloring is
/// emitted separately by the caller, so nothing legitimate is lost here.
///
/// Strips C0 controls and DEL, plus C1 controls in their two-byte UTF-8 form
/// (0xC2 0x80-0x9F) since a bare 0x80-0x9F byte is a UTF-8 continuation byte
/// that would corrupt multi-byte characters if dropped on its own. Tabs are
/// always kept; newlines only when `allow_newlines` is set (false for
/// single-line contexts like a description, where a newline would break the
/// listing layout).
pub fn writeSanitized(out: *std.Io.Writer, s: []const u8, allow_newlines: bool) !void {
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == 0xC2 and i + 1 < s.len and s[i + 1] >= 0x80 and s[i + 1] <= 0x9F) {
            i += 2; // C1 control, encoded as two UTF-8 bytes
            continue;
        }
        i += 1;
        if (c == '\n') {
            try out.writeByte(if (allow_newlines) '\n' else ' ');
            continue;
        }
        if (c == '\t') {
            try out.writeByte('\t');
            continue;
        }
        if (c < 0x20 or c == 0x7F) continue;
        try out.writeByte(c);
    }
}

/// Builds a short, badge-stripped excerpt from a full README for the
/// collapsed REPL view. Shared by github.zig/gitlab.zig so both hosts produce
/// excerpts the same way.
pub fn makeExcerpt(allocator: std.mem.Allocator, full_readme: []const u8, max_bytes: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, full_readme, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "[![")) continue; // badge/shield link
        if (std.mem.startsWith(u8, line, "![")) continue; // plain image
        if (std.mem.startsWith(u8, line, "<img")) continue;
        if (std.mem.startsWith(u8, line, "<p align")) continue; // common badge-row wrapper

        if (out.items.len > 0) try out.append(allocator, '\n');
        try out.appendSlice(allocator, line);
        if (out.items.len >= max_bytes) break;
    }

    const capped = if (out.items.len > max_bytes) out.items[0..max_bytes] else out.items;
    return try allocator.dupe(u8, capped);
}

/// Safe accessor for a string field on a parsed JSON object -- null if the
/// key is missing or holds a non-string value, instead of panicking.
pub fn jsonStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

/// Same, for an integer field, with a default for missing/wrong-typed values.
pub fn jsonInt(obj: std.json.ObjectMap, key: []const u8, default: i64) i64 {
    const v = obj.get(key) orelse return default;
    if (v != .integer) return default;
    return v.integer;
}

/// Same, for a float field -- handles both `.float` and `.integer` JSON
/// tokens (NVD's CVSS baseScore is "9.8" in some responses but a whole
/// number like "10.0" in others; std.json only tags a token `.float` when it
/// actually saw a decimal point/exponent), defaulting to null when missing
/// or non-numeric.
pub fn jsonFloat(obj: std.json.ObjectMap, key: []const u8) ?f64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

/// Trims an ISO-8601 timestamp ("2023-10-10T21:40:09Z") down to just the
/// date portion for a cleaner listing. Returns the input unchanged if it
/// doesn't contain a 'T' (already date-only, or unrecognized/empty).
pub fn dateOnly(iso: []const u8) []const u8 {
    const t = std.mem.indexOfScalar(u8, iso, 'T') orelse return iso;
    return iso[0..t];
}

/// True only if the subprocess ran to completion and exited 0.
pub fn termOk(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "Host.fromLabel accepts short and long forms, rejects garbage" {
    try std.testing.expectEqual(Host.github, Host.fromLabel("gh").?);
    try std.testing.expectEqual(Host.github, Host.fromLabel("github").?);
    try std.testing.expectEqual(Host.gitlab, Host.fromLabel("glab").?);
    try std.testing.expectEqual(Host.gitlab, Host.fromLabel("gitlab").?);
    try std.testing.expectEqual(Host.codeberg, Host.fromLabel("cb").?);
    try std.testing.expectEqual(Host.codeberg, Host.fromLabel("codeberg").?);
    try std.testing.expectEqual(@as(?Host, null), Host.fromLabel("bitbucket"));
}

test "looksRateLimited fires on 403/429 status regardless of body" {
    try std.testing.expect(looksRateLimited(.forbidden, "{}"));
    try std.testing.expect(looksRateLimited(.too_many_requests, "{}"));
    try std.testing.expect(!looksRateLimited(.internal_server_error, "{}")); // gitlab's known empty-search 500
    try std.testing.expect(!looksRateLimited(.ok, "{\"items\":[]}"));
}

test "looksRateLimited falls back to body text when no status is available (CLI mode)" {
    try std.testing.expect(looksRateLimited(null, "{\"message\":\"API rate limit exceeded for 1.2.3.4.\"}"));
    try std.testing.expect(looksRateLimited(null, "you have hit the secondary Rate Limit, please wait"));
    try std.testing.expect(!looksRateLimited(null, "{\"message\":\"Not Found\"}"));
}

test "sanitizeDirName replaces unsafe characters, keeps alnum/-/_" {
    const allocator = std.testing.allocator;
    const out = try sanitizeDirName(allocator, "confluence CVE (generic)!");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("confluence-CVE--generic--", out);
}

test "sanitizePathComponent keeps ordinary repo names but defuses traversal" {
    const allocator = std.testing.allocator;

    // Dots inside a name are normal and must survive.
    const plain = try sanitizePathComponent(allocator, "log4j-shell-poc.py");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("log4j-shell-poc.py", plain);

    // Separators and traversal sequences must not survive.
    const traversal = try sanitizePathComponent(allocator, "../../etc/cron.d");
    defer allocator.free(traversal);
    try std.testing.expectEqualStrings("-------etc-cron.d", traversal);
    try std.testing.expect(std.mem.indexOf(u8, traversal, "..") == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, traversal, '/') == null);

    // A leading dot would make a hidden file (or be "."/".." outright).
    const dotfile = try sanitizePathComponent(allocator, ".ssh");
    defer allocator.free(dotfile);
    try std.testing.expectEqualStrings("-ssh", dotfile);

    const dotdot = try sanitizePathComponent(allocator, "..");
    defer allocator.free(dotdot);
    try std.testing.expectEqualStrings("--", dotdot);

    // Empty input must not produce an empty path segment.
    const empty = try sanitizePathComponent(allocator, "");
    defer allocator.free(empty);
    try std.testing.expectEqualStrings("unnamed", empty);
}

test "writeSanitized strips terminal control bytes from remote text" {
    const allocator = std.testing.allocator;
    var buf: std.Io.Writer.Allocating = .init(allocator);
    defer buf.deinit();

    // An escape sequence that would otherwise erase the line it was printed
    // on, plus an OSC 52 clipboard write.
    try writeSanitized(&buf.writer, "safe\x1b[2K\x1b]52;c;cGF5bG9hZA==\x07end", true);
    try std.testing.expectEqualStrings("safe[2K]52;c;cGF5bG9hZA==end", buf.written());

    // Newlines collapse to spaces in single-line contexts, survive otherwise.
    buf.clearRetainingCapacity();
    try writeSanitized(&buf.writer, "one\ntwo", false);
    try std.testing.expectEqualStrings("one two", buf.written());

    buf.clearRetainingCapacity();
    try writeSanitized(&buf.writer, "one\ntwo", true);
    try std.testing.expectEqualStrings("one\ntwo", buf.written());

    // C1 controls arrive as two UTF-8 bytes; dropping only the second would
    // corrupt the stream, so the pair goes together. Real multi-byte
    // characters must be untouched.
    buf.clearRetainingCapacity();
    try writeSanitized(&buf.writer, "a\xc2\x9bm caf\xc3\xa9", true);
    try std.testing.expectEqualStrings("am caf\xc3\xa9", buf.written());
}

test "dateOnly trims the time portion off an ISO-8601 timestamp" {
    try std.testing.expectEqualStrings("2023-10-10", dateOnly("2023-10-10T21:40:09Z"));
    try std.testing.expectEqualStrings("2026-01-16", dateOnly("2026-01-16T10:41:52.576Z"));
    try std.testing.expectEqualStrings("", dateOnly(""));
}

test "makeExcerpt strips badges/images and caps length" {
    const allocator = std.testing.allocator;
    const readme =
        \\[![Build](https://img.shields.io/badge/build-passing-green)](https://example.com)
        \\![banner](banner.png)
        \\
        \\# Real Title
        \\
        \\Some real description text that should survive.
    ;
    const excerpt = try makeExcerpt(allocator, readme, 500);
    defer allocator.free(excerpt);

    try std.testing.expect(std.mem.indexOf(u8, excerpt, "shields.io") == null);
    try std.testing.expect(std.mem.indexOf(u8, excerpt, "banner.png") == null);
    try std.testing.expect(std.mem.indexOf(u8, excerpt, "# Real Title") != null);
    try std.testing.expect(std.mem.indexOf(u8, excerpt, "should survive") != null);
}
