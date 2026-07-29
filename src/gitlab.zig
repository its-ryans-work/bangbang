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
            std.debug.print("warn: glab search failed for {s}: {s}\n", .{ query, @errorName(err) });
            return .{ .hits = &.{} };
        },
        .token => |t| blk: {
            const r = searchViaHttp(allocator, io, query, per_page, t) catch |err| {
                std.debug.print("warn: gitlab search failed for {s}: {s}\n", .{ query, @errorName(err) });
                return .{ .hits = &.{} };
            };
            status = r.status;
            break :blk r.body;
        },
        .none => blk: {
            const r = searchViaHttp(allocator, io, query, per_page, null) catch |err| {
                std.debug.print("warn: gitlab search failed for {s}: {s}\n", .{ query, @errorName(err) });
                return .{ .hits = &.{} };
            };
            status = r.status;
            break :blk r.body;
        },
    };

    return .{
        .hits = try parseSearchBody(allocator, body),
        // gitlab.com's known 500-for-empty-search quirk (see searchViaHttp)
        // means looksRateLimited must never treat 500 as a signal -- it
        // only fires on 403/429, so that behavior is unaffected here.
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
    // Must percent-encode the query before it reaches `glab api` -- see the
    // identical fix (and the confirmed-live-hang explanation) in
    // github.zig's searchViaCli. Untested with a raw multi-word query here
    // specifically, but the underlying "gh/glab api" argument-handling issue
    // is the same tool family, so applying the same fix defensively.
    var path_buf: std.Io.Writer.Allocating = .init(allocator);
    defer path_buf.deinit();
    try path_buf.writer.writeAll("projects?search=");
    try (std.Uri.Component{ .raw = cve_str }).formatQuery(&path_buf.writer);
    try path_buf.writer.print("&order_by=id&sort=desc&per_page={d}", .{per_page});
    const path = path_buf.written();

    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "glab", "api", path },
        .stdout_limit = .limited(8 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    // Same story as gh: a non-zero exit with SOME stdout is still useful
    // (an error/message body parseSearchBody will read as zero hits) --
    // only a totally empty body is worth surfacing as a hard error.
    if (result.stdout.len == 0 and !forge.termOk(result.term)) return error.GlabApiFailed;
    return result.stdout;
}

fn searchViaHttp(allocator: std.mem.Allocator, io: std.Io, cve_str: []const u8, per_page: usize, token: ?[]const u8) !HttpBody {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var url: std.Io.Writer.Allocating = .init(allocator);
    defer url.deinit();
    try url.writer.writeAll("https://gitlab.com/api/v4/projects?search=");
    try (std.Uri.Component{ .raw = cve_str }).formatQuery(&url.writer);
    try url.writer.print("&order_by=id&sort=desc&per_page={d}", .{per_page});

    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    if (token) |t| try headers.append(allocator, .{ .name = "PRIVATE-TOKEN", .value = t });

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();

    // gitlab.com returns HTTP 500 (not an empty array) when a search matches
    // nothing (confirmed live). The status is still captured and returned
    // now (for rate-limit detection, which only fires on 403/429 -- see
    // forge.looksRateLimited), but parseSearchBody itself keeps ignoring it
    // and treats anything that isn't a JSON array as zero hits, same as
    // before. A hard network failure still propagates via `try` on the
    // outer catch in `search()`.
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
    if (parsed.value != .array) return &.{}; // error object (rate limit, 500-as-message) -> zero hits

    var hits: std.ArrayList(forge.RepoHit) = .empty;
    defer hits.deinit(allocator);

    for (parsed.value.array.items) |item| {
        if (item != .object) continue;
        const o = item.object;

        const full_name_json = forge.jsonStr(o, "path_with_namespace") orelse continue;
        // GitLab namespaces can be nested (group/subgroup/repo), so split on
        // the *last* slash to separate "repo name" from "everything else".
        const last_slash = std.mem.lastIndexOfScalar(u8, full_name_json, '/') orelse continue;

        // Dupe out of the JSON parse arena (freed when this function
        // returns) into the caller's allocator before parsed.deinit() runs.
        const full_name = try allocator.dupe(u8, full_name_json);
        const description = try allocator.dupe(u8, forge.jsonStr(o, "description") orelse "");
        const default_branch = try allocator.dupe(u8, forge.jsonStr(o, "default_branch") orelse "main");
        const stars_i64 = forge.jsonInt(o, "star_count", 0);
        const forks_i64 = forge.jsonInt(o, "forks_count", 0);
        const created_at = try allocator.dupe(u8, forge.dateOnly(forge.jsonStr(o, "created_at") orelse ""));
        const readme_path = extractReadmePath(allocator, forge.jsonStr(o, "readme_url"), default_branch) catch "";

        const repo_url = if (forge.jsonStr(o, "web_url")) |u|
            try allocator.dupe(u8, u)
        else
            try std.fmt.allocPrint(allocator, "https://gitlab.com/{s}", .{full_name});

        const owner_url = if (o.get("namespace")) |nv| blk: {
            if (nv != .object) break :blk try std.fmt.allocPrint(allocator, "https://gitlab.com/{s}", .{full_name[0..last_slash]});
            const u = forge.jsonStr(nv.object, "web_url") orelse break :blk try std.fmt.allocPrint(allocator, "https://gitlab.com/{s}", .{full_name[0..last_slash]});
            break :blk try allocator.dupe(u8, u);
        } else try std.fmt.allocPrint(allocator, "https://gitlab.com/{s}", .{full_name[0..last_slash]});

        try hits.append(allocator, .{
            .host = .gitlab,
            .owner = full_name[0..last_slash],
            .name = full_name[last_slash + 1 ..],
            .full_name = full_name,
            .stars = @intCast(std.math.clamp(stars_i64, 0, std.math.maxInt(u32))),
            .description = description,
            .readme_excerpt = "",
            .readme_full = "",
            .gitlab_default_branch = default_branch,
            .gitlab_readme_path = readme_path,
            .forks = @intCast(std.math.clamp(forks_i64, 0, std.math.maxInt(u32))),
            .created_at = created_at,
            .repo_url = repo_url,
            .owner_url = owner_url,
        });
    }

    return try hits.toOwnedSlice(allocator);
}

/// `readme_url` looks like ".../-/blob/<default_branch>/<path>" -- pulling
/// `<path>` out of it (rather than a separate tree-listing call) gets us the
/// exact readme filename/casing/subdirectory for free.
fn extractReadmePath(allocator: std.mem.Allocator, readme_url_opt: ?[]const u8, default_branch: []const u8) ![]const u8 {
    const readme_url = readme_url_opt orelse return "";
    var marker_buf: [128]u8 = undefined;
    const marker = std.fmt.bufPrint(&marker_buf, "/-/blob/{s}/", .{default_branch}) catch return "";
    const idx = std.mem.indexOf(u8, readme_url, marker) orelse return "";
    return try allocator.dupe(u8, readme_url[idx + marker.len ..]);
}

/// Fetches the readme found at search time (if any) and fills in
/// readme_full/readme_excerpt in place. Best-effort: no readme_path, or a
/// fetch failure, just leaves the excerpt/full text empty.
pub fn fetchReadme(allocator: std.mem.Allocator, io: std.Io, mode: auth.AuthMode, hit: *forge.RepoHit) void {
    if (hit.gitlab_readme_path.len == 0) return;
    const full = fetchReadmeRaw(allocator, io, mode, hit.full_name, hit.gitlab_default_branch, hit.gitlab_readme_path) catch return;
    hit.readme_full = full[0..@min(full.len, full_readme_bytes)];
    hit.readme_excerpt = forge.makeExcerpt(allocator, full, excerpt_bytes) catch "";
}

fn fetchReadmeRaw(
    allocator: std.mem.Allocator,
    io: std.Io,
    mode: auth.AuthMode,
    full_name: []const u8,
    branch: []const u8,
    readme_path: []const u8,
) ![]const u8 {
    return switch (mode) {
        .cli => readmeViaCli(allocator, io, full_name, branch, readme_path),
        .token => |t| readmeViaHttp(allocator, io, full_name, branch, readme_path, t),
        .none => readmeViaHttp(allocator, io, full_name, branch, readme_path, null),
    };
}

/// GitLab requires internal slashes in both the project identifier
/// ("namespace/repo") and a nested file path to be percent-encoded as %2F --
/// std.Uri.Component's formatters deliberately leave '/' alone (confirmed:
/// they're built for query values and path *segments*, not a single segment
/// standing in for a full path), so this is a small dedicated encoder.
fn gitlabPathEncode(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| {
        if (c == '/') {
            try w.writeAll("%2F");
        } else if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

fn buildReadmeApiPath(allocator: std.mem.Allocator, full_name: []const u8, branch: []const u8, readme_path: []const u8) ![]const u8 {
    var w: std.Io.Writer.Allocating = .init(allocator);
    defer w.deinit();
    try w.writer.writeAll("projects/");
    try gitlabPathEncode(&w.writer, full_name);
    try w.writer.writeAll("/repository/files/");
    try gitlabPathEncode(&w.writer, readme_path);
    try w.writer.writeAll("/raw?ref=");
    try (std.Uri.Component{ .raw = branch }).formatQuery(&w.writer);

    var al = w.toArrayList();
    return try al.toOwnedSlice(allocator);
}

fn readmeViaCli(allocator: std.mem.Allocator, io: std.Io, full_name: []const u8, branch: []const u8, readme_path: []const u8) ![]const u8 {
    const path = try buildReadmeApiPath(allocator, full_name, branch, readme_path);
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "glab", "api", path },
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(16 * 1024),
    });
    if (!forge.termOk(result.term)) return error.GlabReadmeFailed;
    return result.stdout;
}

fn readmeViaHttp(
    allocator: std.mem.Allocator,
    io: std.Io,
    full_name: []const u8,
    branch: []const u8,
    readme_path: []const u8,
    token: ?[]const u8,
) ![]const u8 {
    const path = try buildReadmeApiPath(allocator, full_name, branch, readme_path);
    const url = try std.fmt.allocPrint(allocator, "https://gitlab.com/api/v4/{s}", .{path});

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var headers: std.ArrayList(std.http.Header) = .empty;
    defer headers.deinit(allocator);
    if (token) |t| try headers.append(allocator, .{ .name = "PRIVATE-TOKEN", .value = t });

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .extra_headers = headers.items,
        .response_writer = &body.writer,
    });
    if (result.status != .ok) return error.GitlabReadmeRequestFailed;

    var al = body.toArrayList();
    return try al.toOwnedSlice(allocator);
}

/// Clones `hit` into `dest_dir` using the active auth tier: the `glab` CLI
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
            .argv = &.{ "glab", "repo", "clone", hit.full_name, dest_dir },
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        }),
        .token, .none => blk: {
            const url = try std.fmt.allocPrint(allocator, "https://gitlab.com/{s}.git", .{hit.full_name});
            var env = try auth.gitCloneEnv(allocator, environ, .gitlab, token);
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

test "gitlabPathEncode escapes slashes as %2F and passes safe chars through" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try gitlabPathEncode(&w, ".github/READ ME.md");
    try std.testing.expectEqualStrings(".github%2FREAD%20ME.md", w.buffered());
}

test "extractReadmePath pulls the path out of a blob URL" {
    const allocator = std.testing.allocator;
    const url = "https://gitlab.com/ns/repo/-/blob/main/README.md";
    const path = try extractReadmePath(allocator, url, "main");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("README.md", path);
}

test "extractReadmePath returns empty for a repo with no readme" {
    const path = try extractReadmePath(std.testing.allocator, null, "main");
    try std.testing.expectEqualStrings("", path);
}

test "parseSearchBody splits nested namespaces on the last slash" {
    const allocator = std.testing.allocator;
    const body =
        \\[{"path_with_namespace":"group/subgroup/repo","star_count":5,"forks_count":2,
        \\  "created_at":"2026-01-16T10:41:52.576Z","description":"d",
        \\  "default_branch":"main","readme_url":"https://gitlab.com/group/subgroup/repo/-/blob/main/README.md",
        \\  "web_url":"https://gitlab.com/group/subgroup/repo",
        \\  "namespace":{"web_url":"https://gitlab.com/groups/group/subgroup"}}]
    ;
    const hits = try parseSearchBody(allocator, body);
    defer {
        for (hits) |h| {
            allocator.free(h.full_name);
            allocator.free(h.description);
            allocator.free(h.gitlab_default_branch);
            allocator.free(h.created_at);
            allocator.free(h.repo_url);
            allocator.free(h.owner_url);
            if (h.gitlab_readme_path.len > 0) allocator.free(h.gitlab_readme_path);
        }
        allocator.free(hits);
    }

    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expectEqualStrings("group/subgroup", hits[0].owner);
    try std.testing.expectEqualStrings("repo", hits[0].name);
    try std.testing.expectEqualStrings("README.md", hits[0].gitlab_readme_path);
    try std.testing.expectEqual(@as(u32, 2), hits[0].forks);
    try std.testing.expectEqualStrings("2026-01-16", hits[0].created_at);
    try std.testing.expectEqualStrings("https://gitlab.com/group/subgroup/repo", hits[0].repo_url);
    try std.testing.expectEqualStrings("https://gitlab.com/groups/group/subgroup", hits[0].owner_url);
}

test "parseSearchBody treats a 500-as-message object as zero hits" {
    const allocator = std.testing.allocator;
    const body = "{\"message\":\"500 Internal Server Error\"}";
    const hits = try parseSearchBody(allocator, body);
    defer allocator.free(hits);
    try std.testing.expectEqual(@as(usize, 0), hits.len);
}
