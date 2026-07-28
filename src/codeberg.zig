const std = @import("std");
const cve = @import("cve.zig");
const forge = @import("forge.zig");
const auth = @import("auth.zig");

const excerpt_bytes = 500;
const full_readme_bytes = 4000;

/// Codeberg (a Forgejo/Gitea instance) has no dedicated CLI tool in wide use
/// (unlike gh/glab), so unlike github.zig/gitlab.zig there is no `.cli`
/// branch here -- auth.resolve() never returns `.cli` for `.codeberg`
/// (clientIdVarFor returns null so device-flow is skipped too, and there's
/// no CLI to probe), but if `.cli` somehow arrived anyway it's treated the
/// same as `.none` rather than erroring.

/// Candidate hits for `query` (either a CVE ID string or an arbitrary
/// keyword -- see the `<keyword> CVE` fallback search in main.zig).
/// Over-fetches relative to `max_hits` the same way github.zig/gitlab.zig do.
pub fn search(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, query: []const u8, per_page: usize) !forge.SearchResult {
    const token: ?[]const u8 = switch (mode) {
        .token => |t| t,
        .cli, .none => null,
    };
    const r = searchViaHttp(allocator, io, query, per_page, token) catch |err| {
        std.debug.print("warn: codeberg search failed for {s}: {s}\n", .{ query, @errorName(err) });
        return .{ .hits = &.{} };
    };
    return .{
        .hits = try parseSearchBody(allocator, r.body),
        .rate_limited = forge.looksRateLimited(r.status, r.body),
    };
}

/// Same as `search`, but takes a CveId directly (thin wrapper matching
/// github.zig/gitlab.zig's call shape for the per-CVE pipeline).
pub fn searchCve(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, cve_id: cve.CveId, per_page: usize) !forge.SearchResult {
    var cve_buf: [16]u8 = undefined;
    return search(allocator, io, mode, try cve_id.toSlice(&cve_buf), per_page);
}

const HttpBody = struct { body: []u8, status: std.http.Status };

fn searchViaHttp(allocator: std.mem.Allocator, io: std.Io, query: []const u8, per_page: usize, token: ?[]const u8) !HttpBody {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var url: std.Io.Writer.Allocating = .init(allocator);
    defer url.deinit();
    try url.writer.writeAll("https://codeberg.org/api/v1/repos/search?q=");
    try (std.Uri.Component{ .raw = query }).formatQuery(&url.writer);
    try url.writer.print("&limit={d}", .{per_page});

    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    var auth_header_buf: [128]u8 = undefined;
    if (token) |t| {
        const v = try std.fmt.bufPrint(&auth_header_buf, "token {s}", .{t});
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

    const data_val = parsed.value.object.get("data") orelse return &.{};
    if (data_val != .array) return &.{};

    var hits: std.ArrayList(forge.RepoHit) = .empty;
    defer hits.deinit(allocator);

    for (data_val.array.items) |item| {
        if (item != .object) continue;
        const o = item.object;

        const full_name_json = forge.jsonStr(o, "full_name") orelse continue;
        const slash = std.mem.indexOfScalar(u8, full_name_json, '/') orelse continue;

        // Dupe out of the JSON parse arena (freed when this function
        // returns) into the caller's allocator before parsed.deinit() runs.
        const full_name = try allocator.dupe(u8, full_name_json);
        const description = try allocator.dupe(u8, forge.jsonStr(o, "description") orelse "");
        const stars_i64 = forge.jsonInt(o, "stars_count", 0); // note: "stars_count", not GitHub's "stargazers_count"
        const forks_i64 = forge.jsonInt(o, "forks_count", 0);
        const created_at = try allocator.dupe(u8, forge.dateOnly(forge.jsonStr(o, "created_at") orelse ""));

        const repo_url = if (forge.jsonStr(o, "html_url")) |u|
            try allocator.dupe(u8, u)
        else
            try std.fmt.allocPrint(allocator, "https://codeberg.org/{s}", .{full_name});

        const owner_url = if (o.get("owner")) |ov| blk: {
            if (ov != .object) break :blk try std.fmt.allocPrint(allocator, "https://codeberg.org/{s}", .{full_name[0..slash]});
            const u = forge.jsonStr(ov.object, "html_url") orelse break :blk try std.fmt.allocPrint(allocator, "https://codeberg.org/{s}", .{full_name[0..slash]});
            break :blk try allocator.dupe(u8, u);
        } else try std.fmt.allocPrint(allocator, "https://codeberg.org/{s}", .{full_name[0..slash]});

        try hits.append(allocator, .{
            .host = .codeberg,
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

/// Codeberg/Forgejo has no GitHub-style auto-resolving readme endpoint (a
/// direct `/readme` request 404s -- confirmed live) and no GitLab-style
/// `readme_url` in the search response either. Lists the repo root and picks
/// the first entry whose name matches /^readme/i, then fetches its
/// `download_url` directly -- that URL already returns plain raw text, no
/// JSON/base64 wrapping (confirmed live).
pub fn fetchReadme(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, hit: *forge.RepoHit) void {
    const full = fetchReadmeRaw(allocator, io, mode, hit.full_name) catch return;
    hit.readme_full = full[0..@min(full.len, full_readme_bytes)];
    hit.readme_excerpt = forge.makeExcerpt(allocator, full, excerpt_bytes) catch "";
}

fn tokenHeader(buf: []u8, token: ?[]const u8) ?std.http.Header {
    const t = token orelse return null;
    const v = std.fmt.bufPrint(buf, "token {s}", .{t}) catch return null;
    return .{ .name = "Authorization", .value = v };
}

fn fetchReadmeRaw(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, full_name: []const u8) ![]const u8 {
    const token: ?[]const u8 = switch (mode) {
        .token => |t| t,
        .cli, .none => null,
    };

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var auth_header_buf: [128]u8 = undefined;
    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    if (tokenHeader(&auth_header_buf, token)) |h| try headers.append(allocator, h);

    var contents_url_buf: [256]u8 = undefined;
    const contents_url = try std.fmt.bufPrint(&contents_url_buf, "https://codeberg.org/api/v1/repos/{s}/contents", .{full_name});

    var listing_body: std.Io.Writer.Allocating = .init(allocator);
    defer listing_body.deinit();
    const listing_result = try client.fetch(.{
        .location = .{ .url = contents_url },
        .extra_headers = headers.items,
        .response_writer = &listing_body.writer,
    });
    if (listing_result.status != .ok) return error.CodebergContentsRequestFailed;

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, listing_body.written(), .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.UnexpectedCodebergResponse;

    var download_url: ?[]const u8 = null;
    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const o = item.object;
        const name = forge.jsonStr(o, "name") orelse continue;
        const kind = forge.jsonStr(o, "type") orelse continue;
        if (!std.mem.eql(u8, kind, "file")) continue;
        if (!std.ascii.startsWithIgnoreCase(name, "readme")) continue;
        download_url = forge.jsonStr(o, "download_url") orelse continue;
        break;
    }
    const raw_url = download_url orelse return error.NoReadmeFound;
    const owned_url = try allocator.dupe(u8, raw_url);

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = owned_url },
        .extra_headers = headers.items,
        .response_writer = &body.writer,
    });
    if (result.status != .ok) return error.CodebergReadmeRequestFailed;

    var al = body.toArrayList();
    return try al.toOwnedSlice(allocator);
}

/// Clones `hit` via plain `git clone` (no CLI tool to shell out to). With a
/// token, embeds it Gitea/Forgejo-style (`token:<PAT>@host`); anonymous
/// otherwise -- fine, since PoC repos are almost always public.
pub fn clone(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, hit: forge.RepoHit, dest_dir: []const u8) !void {
    const token: ?[]const u8 = switch (mode) {
        .token => |t| t,
        .cli, .none => null,
    };

    const url = if (token) |t|
        try std.fmt.allocPrint(allocator, "https://token:{s}@codeberg.org/{s}.git", .{ t, hit.full_name })
    else
        try std.fmt.allocPrint(allocator, "https://codeberg.org/{s}.git", .{hit.full_name});

    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "clone", "--depth", "1", url, dest_dir },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    if (!forge.termOk(result.term)) {
        std.debug.print("{s}\n", .{result.stderr});
        return error.CloneFailed;
    }
}

test "parseSearchBody reads Codeberg's {ok,data} wrapper and stars_count field name" {
    const allocator = std.testing.allocator;
    const body =
        \\{"ok":true,"data":[
        \\  {"full_name":"temppet/-CVE-2017-0785-BlueBorne-PoC","stars_count":3,"forks_count":1,
        \\   "created_at":"2024-08-07T09:08:56+02:00","description":"CVE-2017-0785 BlueBorne PoC",
        \\   "html_url":"https://codeberg.org/temppet/-CVE-2017-0785-BlueBorne-PoC",
        \\   "owner":{"html_url":"https://codeberg.org/temppet"}}
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
    try std.testing.expectEqualStrings("temppet", hits[0].owner);
    try std.testing.expectEqualStrings("-CVE-2017-0785-BlueBorne-PoC", hits[0].name);
    try std.testing.expectEqual(@as(u32, 3), hits[0].stars);
    try std.testing.expectEqual(@as(u32, 1), hits[0].forks);
    try std.testing.expectEqualStrings("2024-08-07", hits[0].created_at);
}

test "parseSearchBody treats a non-array data field as zero hits" {
    const allocator = std.testing.allocator;
    const body = "{\"ok\":false,\"message\":\"some error\"}";
    const hits = try parseSearchBody(allocator, body);
    defer allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}
