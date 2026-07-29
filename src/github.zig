const std = @import("std");
const cve = @import("cve.zig");
const forge = @import("forge.zig");
const auth = @import("auth.zig");

const excerpt_bytes = 500;
const full_readme_bytes = 4000;

/// Candidate hits for an arbitrary query string, auth-tier aware.
/// Over-fetches relative to `max_hits` (caller passes a 3x-oversampled page
/// size) so filter.zig's dump-repo removal still leaves close to `max_hits`
/// good results.
pub fn search(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, query: []const u8, per_page: usize) !forge.SearchResult {
    var status: ?std.http.Status = null;
    const body: []const u8 = switch (mode) {
        .cli => searchViaCli(allocator, io, query, per_page) catch |err| {
            std.debug.print("warn: gh search failed for {s}: {s}\n", .{ query, @errorName(err) });
            return .{ .hits = &.{} };
        },
        .token => |t| blk: {
            const r = searchViaHttp(allocator, io, query, per_page, t) catch |err| {
                std.debug.print("warn: github search failed for {s}: {s}\n", .{ query, @errorName(err) });
                return .{ .hits = &.{} };
            };
            status = r.status;
            break :blk r.body;
        },
        .none => blk: {
            const r = searchViaHttp(allocator, io, query, per_page, null) catch |err| {
                std.debug.print("warn: github search failed for {s}: {s}\n", .{ query, @errorName(err) });
                return .{ .hits = &.{} };
            };
            status = r.status;
            break :blk r.body;
        },
    };

    return .{
        .hits = try parseSearchBody(allocator, body),
        .rate_limited = forge.looksRateLimited(status, body),
    };
}

/// Same as `search`, but takes a CveId directly (thin wrapper matching the
/// per-CVE pipeline's call shape).
pub fn searchCve(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, cve_id: cve.CveId, per_page: usize) !forge.SearchResult {
    var cve_buf: [16]u8 = undefined;
    return search(allocator, io, mode, try cve_id.toSlice(&cve_buf), per_page);
}

const HttpBody = struct { body: []u8, status: std.http.Status };

fn searchViaCli(allocator: std.mem.Allocator, io: std.Io, cve_str: []const u8, per_page: usize) ![]u8 {
    // The query must be percent-encoded before hitting `gh api` -- an
    // unescaped space in a multi-word query (e.g. the zero-hits fallback
    // search's "<keyword> CVE") makes `gh api` hang indefinitely rather than
    // erroring (confirmed live: reproduced the exact hang with a bare `gh
    // api "...q=confluence CVE..."` call). CVE-ID queries never hit this
    // because they have no characters needing encoding.
    var path_buf: std.Io.Writer.Allocating = .init(allocator);
    defer path_buf.deinit();
    try path_buf.writer.writeAll("search/repositories?q=");
    try (std.Uri.Component{ .raw = cve_str }).formatQuery(&path_buf.writer);
    try path_buf.writer.print("&sort=stars&order=desc&per_page={d}", .{per_page});
    const path = path_buf.written();

    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "gh", "api", path },
        .stdout_limit = .limited(8 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    // `gh api` exits non-zero on 4xx/5xx; that's still useful JSON (a rate
    // limit / error message) for parseSearchBody to shrug off as zero hits,
    // so don't fail the whole search over it -- only a totally empty body
    // (couldn't even run) is worth surfacing as an error.
    if (result.stdout.len == 0 and !forge.termOk(result.term)) return error.GhApiFailed;
    return result.stdout;
}

fn searchViaHttp(allocator: std.mem.Allocator, io: std.Io, cve_str: []const u8, per_page: usize, token: ?[]const u8) !HttpBody {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var url: std.Io.Writer.Allocating = .init(allocator);
    defer url.deinit();
    try url.writer.writeAll("https://api.github.com/search/repositories?q=");
    try (std.Uri.Component{ .raw = cve_str }).formatQuery(&url.writer);
    try url.writer.print("&sort=stars&order=desc&per_page={d}", .{per_page});

    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    try headers.append(allocator, .{ .name = "Accept", .value = "application/vnd.github+json" });
    try headers.append(allocator, .{ .name = "User-Agent", .value = "bangbang-cve-hunter" });
    var auth_header_buf: [128]u8 = undefined;
    if (token) |t| {
        const v = try std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{t});
        try headers.append(allocator, .{ .name = "Authorization", .value = v });
    }

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url.written() },
        .extra_headers = headers.items,
        .response_writer = &body.writer,
    });

    var al = body.toArrayList();
    return .{ .body = try al.toOwnedSlice(allocator), .status = result.status };
}

fn parseSearchBody(allocator: std.mem.Allocator, body: []const u8) ![]forge.RepoHit {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return &.{};
    defer parsed.deinit();
    if (parsed.value != .object) return &.{};

    const obj = parsed.value.object;
    // GitHub returns {"message": "..."} for rate limits / bad queries instead
    // of an items array -- treat as zero hits rather than failing the CVE.
    const items_val = obj.get("items") orelse return &.{};
    if (items_val != .array) return &.{};

    var hits: std.ArrayList(forge.RepoHit) = .empty;
    defer hits.deinit(allocator);

    for (items_val.array.items) |item| {
        if (item != .object) continue;
        const o = item.object;

        const full_name_json = forge.jsonStr(o, "full_name") orelse continue;
        const slash = std.mem.indexOfScalar(u8, full_name_json, '/') orelse continue;

        // Dupe out of the JSON parse arena (freed when this function
        // returns) into the caller's allocator before parsed.deinit() runs.
        const full_name = try allocator.dupe(u8, full_name_json);
        const description = try allocator.dupe(u8, forge.jsonStr(o, "description") orelse "");
        const stars_i64 = forge.jsonInt(o, "stargazers_count", 0);
        const forks_i64 = forge.jsonInt(o, "forks_count", 0);
        const created_at = try allocator.dupe(u8, forge.dateOnly(forge.jsonStr(o, "created_at") orelse ""));

        const repo_url = if (forge.jsonStr(o, "html_url")) |u|
            try allocator.dupe(u8, u)
        else
            try std.fmt.allocPrint(allocator, "https://github.com/{s}", .{full_name});

        const owner_url = if (o.get("owner")) |ov| blk: {
            if (ov != .object) break :blk try std.fmt.allocPrint(allocator, "https://github.com/{s}", .{full_name[0..slash]});
            const u = forge.jsonStr(ov.object, "html_url") orelse break :blk try std.fmt.allocPrint(allocator, "https://github.com/{s}", .{full_name[0..slash]});
            break :blk try allocator.dupe(u8, u);
        } else try std.fmt.allocPrint(allocator, "https://github.com/{s}", .{full_name[0..slash]});

        try hits.append(allocator, .{
            .host = .github,
            .owner = full_name[0..slash],
            .name = full_name[slash + 1 ..],
            .full_name = full_name,
            .stars = @intCast(std.math.clamp(stars_i64, 0, std.math.maxInt(u32))),
            .description = description,
            .readme_excerpt = "",
            .readme_full = "",
            .forks = @intCast(std.math.clamp(forks_i64, 0, std.math.maxInt(u32))),
            .created_at = created_at,
            .repo_url = repo_url,
            .owner_url = owner_url,
        });
    }

    return try hits.toOwnedSlice(allocator);
}

/// Fetches the default README for `hit.full_name` and fills in
/// readme_full/readme_excerpt in place. Best-effort: a repo with no readme
/// (or a fetch failure) just keeps the hit's excerpt/full text empty rather
/// than failing the whole pipeline.
pub fn fetchReadme(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, hit: *forge.RepoHit) void {
    const full = fetchReadmeRaw(allocator, io, mode, hit.full_name) catch return;
    hit.readme_full = full[0..@min(full.len, full_readme_bytes)];
    hit.readme_excerpt = forge.makeExcerpt(allocator, full, excerpt_bytes) catch "";
}

fn fetchReadmeRaw(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, full_name: []const u8) ![]const u8 {
    const b64 = switch (mode) {
        .cli => try readmeB64ViaCli(allocator, io, full_name),
        .token => |t| try readmeB64ViaHttp(allocator, io, full_name, t),
        .none => try readmeB64ViaHttp(allocator, io, full_name, null),
    };
    return decodeGithubReadmeB64(allocator, b64);
}

fn readmeB64ViaCli(allocator: std.mem.Allocator, io: std.Io, full_name: []const u8) ![]const u8 {
    var path_buf: [160]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "repos/{s}/readme", .{full_name});
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "gh", "api", path, "--jq", ".content" },
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(16 * 1024),
    });
    if (!forge.termOk(result.term)) return error.GhReadmeFailed;
    return result.stdout;
}

fn readmeB64ViaHttp(allocator: std.mem.Allocator, io: std.Io, full_name: []const u8, token: ?[]const u8) ![]const u8 {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var url_buf: [200]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "https://api.github.com/repos/{s}/readme", .{full_name});

    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    try headers.append(allocator, .{ .name = "Accept", .value = "application/vnd.github+json" });
    try headers.append(allocator, .{ .name = "User-Agent", .value = "bangbang-cve-hunter" });
    var auth_header_buf: [128]u8 = undefined;
    if (token) |t| {
        const v = try std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{t});
        try headers.append(allocator, .{ .name = "Authorization", .value = v });
    }

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .extra_headers = headers.items,
        .response_writer = &body.writer,
    });
    if (result.status != .ok) return error.GithubReadmeRequestFailed;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body.written(), .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.UnexpectedGithubResponse;
    const content = forge.jsonStr(parsed.value.object, "content") orelse return error.UnexpectedGithubResponse;
    return try allocator.dupe(u8, content);
}

/// GitHub's readme `.content` field is base64 line-wrapped with embedded
/// newlines every ~76 chars, which a plain decoder rejects -- strip
/// whitespace before decoding (confirmed live against a real repo).
fn decodeGithubReadmeB64(allocator: std.mem.Allocator, b64: []const u8) ![]const u8 {
    const stripped = try allocator.alloc(u8, b64.len);
    defer allocator.free(stripped);
    var n: usize = 0;
    for (b64) |c| {
        if (c == '\n' or c == '\r' or c == ' ') continue;
        stripped[n] = c;
        n += 1;
    }
    const clean = stripped[0..n];

    const decoder = std.base64.standard.Decoder;
    const out_len = decoder.calcSizeForSlice(clean) catch return error.BadReadmeBase64;
    const out = try allocator.alloc(u8, out_len);
    decoder.decode(out, clean) catch return error.BadReadmeBase64;
    return out;
}

/// Clones `hit` into `<dest_dir>` using the active auth tier: the `gh` CLI
/// when available (auth handled transparently), otherwise plain `git clone`
/// over HTTPS. Any token travels in the child environment as a scoped
/// Authorization header (see `auth.gitCloneEnv`) rather than in the URL, so
/// it never lands in the cloned repo's `.git/config`, git's error output, or
/// a world-readable argv. Anonymous otherwise -- fine, since PoC repos are
/// almost always public.
pub fn clone(
    allocator: std.mem.Allocator,
    io: std.Io,
    mode: auth.AuthMode,
    hit: forge.RepoHit,
    dest_dir: []const u8,
    environ: *const std.process.Environ.Map,
) !void {
    const token: ?[]const u8 = switch (mode) {
        .token => |t| t,
        .cli, .none => null,
    };

    const result = switch (mode) {
        .cli => try std.process.run(allocator, io, .{
            .argv = &.{ "gh", "repo", "clone", hit.full_name, dest_dir },
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        }),
        .token, .none => blk: {
            const url = try std.fmt.allocPrint(allocator, "https://github.com/{s}.git", .{hit.full_name});
            var env = try auth.gitCloneEnv(allocator, environ, .github, token);
            defer env.deinit();
            break :blk try std.process.run(allocator, io, .{
                .argv = &.{ "git", "clone", "--depth", "1", url, dest_dir },
                .environ_map = &env,
                .stdout_limit = .limited(64 * 1024),
                .stderr_limit = .limited(64 * 1024),
            });
        },
    };
    if (!forge.termOk(result.term)) {
        auth.printRedactedStderr(result.stderr, token);
        return error.CloneFailed;
    }
}

test "decodeGithubReadmeB64 strips embedded newlines before decoding" {
    const allocator = std.testing.allocator;
    // base64 of "# Hello CVE\nworld" split with embedded newlines, as GitHub returns it
    const wrapped = "IyBIZWxsbyBDVkUK\nd29ybGQ=";
    const out = try decodeGithubReadmeB64(allocator, wrapped);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("# Hello CVE\nworld", out);
}

test "parseSearchBody dupes strings out of the JSON arena and splits owner/name" {
    const allocator = std.testing.allocator;
    const body =
        \\{"total_count":1,"items":[
        \\  {"full_name":"Chocapikk/CVE-2023-22515","stargazers_count":154,"forks_count":32,
        \\   "created_at":"2023-10-10T21:40:09Z","description":"Confluence exploit",
        \\   "html_url":"https://github.com/Chocapikk/CVE-2023-22515",
        \\   "owner":{"html_url":"https://github.com/Chocapikk"}}
        \\]}
    ;
    const hits = try parseSearchBody(allocator, body);
    defer {
        for (hits) |h| {
            allocator.free(h.full_name);
            allocator.free(h.description);
            allocator.free(h.created_at);
            allocator.free(h.repo_url);
            allocator.free(h.owner_url);
        }
        allocator.free(hits);
    }

    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("Chocapikk", hits[0].owner);
    try std.testing.expectEqualStrings("CVE-2023-22515", hits[0].name);
    try std.testing.expectEqual(@as(u32, 154), hits[0].stars);
    try std.testing.expectEqual(@as(u32, 32), hits[0].forks);
    try std.testing.expectEqualStrings("2023-10-10", hits[0].created_at);
    try std.testing.expectEqualStrings("https://github.com/Chocapikk/CVE-2023-22515", hits[0].repo_url);
    try std.testing.expectEqualStrings("https://github.com/Chocapikk", hits[0].owner_url);
}

test "parseSearchBody treats a rate-limit message body as zero hits" {
    const allocator = std.testing.allocator;
    const body = "{\"message\":\"API rate limit exceeded\"}";
    const hits = try parseSearchBody(allocator, body);
    defer allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}
