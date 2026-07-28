const std = @import("std");
const builtin = @import("builtin");
const forge = @import("forge.zig");

/// Which of the three ways we're allowed to talk to a host's API/clone
/// endpoints, resolved once per host at startup. `token` covers both the
/// explicit-env-var tier and the device-flow tier -- callers don't need to
/// know which one produced it.
pub const AuthMode = union(enum) {
    cli,
    token: []const u8,
    none,
};

pub fn tokenVarFor(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "GITHUB_TOKEN",
        .gitlab => "GITLAB_TOKEN",
        .codeberg => "CODEBERG_TOKEN",
        .exploitdb => "EXPLOITDB_TOKEN", // unused: exploitdb needs no auth at all, resolve() is never called for it
    };
}

/// null for hosts with no device-flow support -- Codeberg's Forgejo backend
/// has no confirmed RFC 8628 implementation and no widely-used CLI either,
/// so it only ever gets the token/unauthenticated tiers.
pub fn clientIdVarFor(host: forge.Host) ?[]const u8 {
    return switch (host) {
        .github => "BANGBANG_GITHUB_CLIENT_ID",
        .gitlab => "BANGBANG_GITLAB_CLIENT_ID",
        .codeberg => null,
        .exploitdb => null,
    };
}

/// Picks the highest-priority tier that's actually usable for `host`:
/// explicit token env var > persisted token file (wizard-saved PAT, or a
/// prior device-flow login -- see `saveCachedToken`) > authenticated CLI >
/// device-flow (opt-in via a client-id env var, since we can't register an
/// OAuth App on the user's behalf) > unauthenticated. `allocator` is
/// expected to be a long-lived arena -- nothing here frees its own
/// allocations.
pub fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
) !AuthMode {
    if (environ.get(tokenVarFor(host))) |t| {
        if (t.len > 0) return .{ .token = t };
    }

    if (loadCachedToken(allocator, io, environ, host) catch null) |cached| {
        return .{ .token = cached };
    }

    const bin = host.label();
    if (probeCli(allocator, io, bin) and cliAuthenticated(allocator, io, bin)) {
        return .cli;
    }

    if (clientIdVarFor(host)) |client_id_var| {
        if (environ.get(client_id_var)) |client_id| {
            if (client_id.len > 0) {
                const token = try deviceLogin(allocator, io, host, client_id);
                saveCachedToken(allocator, io, environ, host, token) catch |err| {
                    std.debug.print("warn: could not cache {s} device-flow token: {s}\n", .{ host.label(), @errorName(err) });
                };
                return .{ .token = token };
            }
        }
    }

    printNoAuthNotice(host);
    return .none;
}

fn printNoAuthNotice(host: forge.Host) void {
    if (clientIdVarFor(host)) |client_var| {
        std.debug.print(
            "note: no {s} auth configured -- continuing unauthenticated (tighter rate limits). " ++
                "Set {s} (a PAT) for higher limits, or {s} to enable browser login.\n",
            .{ host.label(), tokenVarFor(host), client_var },
        );
        return;
    }
    std.debug.print(
        "note: no {s} auth configured -- continuing unauthenticated (tighter rate limits). " ++
            "Set {s} (a PAT) for higher limits.\n",
        .{ host.label(), tokenVarFor(host) },
    );
}

pub fn probeCli(allocator: std.mem.Allocator, io: std.Io, bin: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ bin, "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch return false;
    return switch (result.term) {
        .exited => true, // ran to completion at all => binary exists and is executable
        else => false,
    };
}

pub fn cliAuthenticated(allocator: std.mem.Allocator, io: std.Io, bin: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ bin, "auth", "status" },
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch return false;
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// `~/.cache/bangbang` -- shared by the per-host token cache below and by
/// wizard.zig's first-run marker file, so there's one canonical location.
pub fn cacheDir(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]const u8 {
    const home = environ.get("HOME") orelse return error.NoHomeDir;
    return std.fmt.allocPrint(allocator, "{s}/.cache/bangbang", .{home});
}

fn cacheFilePath(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map, host: forge.Host) ![]const u8 {
    const dir = try cacheDir(allocator, environ);
    return std.fmt.allocPrint(allocator, "{s}/{s}_token", .{ dir, @tagName(host) });
}

pub fn loadCachedToken(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
) !?[]const u8 {
    const path = try cacheFilePath(allocator, environ, host);
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(8192)) catch return null;
    const trimmed = std.mem.trim(u8, data, " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

/// Deletes the locally-cached token for `host`, if one exists. Returns
/// whether a file actually existed to delete (so callers can report
/// "deleted" vs "nothing to delete" accurately). This only ever touches the
/// local cache file -- it has no way to (and doesn't try to) revoke the
/// token on the host's own side.
pub fn deleteCachedToken(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, host: forge.Host) !bool {
    const path = try cacheFilePath(allocator, environ, host);
    std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    return true;
}

/// `0o600` (owner read/write only) is a POSIX mode bit -- `Io.File.Permissions`
/// is a completely different DWORD/attribute-based type on Windows with no
/// octal-mode concept at all (confirmed against std's own source: its only
/// levers are readOnly/setReadOnly, nothing resembling "restrict to owner").
/// Falls back to the plain default there; the cache dir still isn't
/// world-writable, just not explicitly locked to the owner the way POSIX
/// hosts are.
fn ownerOnlyPermissions() std.Io.File.Permissions {
    return if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
}

pub fn saveCachedToken(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
    token: []const u8,
) !void {
    const dir_path = try cacheDir(allocator, environ);
    try std.Io.Dir.cwd().createDirPath(io, dir_path);

    const file_path = try cacheFilePath(allocator, environ, host);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = file_path,
        .data = token,
        .flags = .{ .permissions = ownerOnlyPermissions() },
    });
}

pub fn openBrowser(allocator: std.mem.Allocator, io: std.Io, url: []const u8) void {
    const argv: []const []const u8 = if (builtin.os.tag == .macos)
        &.{ "open", url }
    else
        &.{ "xdg-open", url };
    _ = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    }) catch {};
}

const DeviceEndpoints = struct {
    code_url: []const u8,
    token_url: []const u8,
    scope: []const u8,
};

fn endpointsFor(host: forge.Host) DeviceEndpoints {
    return switch (host) {
        .github => .{
            .code_url = "https://github.com/login/device/code",
            .token_url = "https://github.com/login/oauth/access_token",
            .scope = "public_repo",
        },
        .gitlab => .{
            .code_url = "https://gitlab.com/oauth/authorize_device",
            .token_url = "https://gitlab.com/oauth/token",
            .scope = "read_api",
        },
        // clientIdVarFor returns null for codeberg and exploitdb, so
        // resolve() never reaches deviceLogin (and therefore this function)
        // for either.
        .codeberg => unreachable,
        .exploitdb => unreachable,
    };
}

fn postForm(allocator: std.mem.Allocator, client: *std.http.Client, url: []const u8, form_body: []const u8) ![]u8 {
    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();

    _ = try client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .extra_headers = &.{
            .{ .name = "Accept", .value = "application/json" },
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
        },
        .payload = form_body,
        .response_writer = &body.writer,
    });

    var al = body.toArrayList();
    return try al.toOwnedSlice(allocator);
}

/// RFC 8628 OAuth Device Authorization flow: request a device code, show the
/// user a short code + open their browser to the verification URL, then poll
/// for the token. This *is* "opens a browser and asks them to log in" -- the
/// direct, no-CLI-required implementation of it.
pub fn deviceLogin(allocator: std.mem.Allocator, io: std.Io, host: forge.Host, client_id: []const u8) ![]const u8 {
    const ep = endpointsFor(host);
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var req1: std.Io.Writer.Allocating = .init(allocator);
    defer req1.deinit();
    try req1.writer.writeAll("client_id=");
    try (std.Uri.Component{ .raw = client_id }).formatQuery(&req1.writer);
    try req1.writer.writeAll("&scope=");
    try (std.Uri.Component{ .raw = ep.scope }).formatQuery(&req1.writer);

    const code_resp = try postForm(allocator, &client, ep.code_url, req1.written());
    const code_parsed = try std.json.parseFromSlice(std.json.Value, allocator, code_resp, .{});
    defer code_parsed.deinit();
    if (code_parsed.value != .object) return error.DeviceFlowBadResponse;
    const co = code_parsed.value.object;

    const device_code = forge.jsonStr(co, "device_code") orelse return error.DeviceFlowBadResponse;
    const user_code = forge.jsonStr(co, "user_code") orelse return error.DeviceFlowBadResponse;
    const verification_uri = forge.jsonStr(co, "verification_uri") orelse return error.DeviceFlowBadResponse;
    var interval_secs = forge.jsonInt(co, "interval", 5);
    const expires_in = forge.jsonInt(co, "expires_in", 900);

    std.debug.print(
        "\n{s} authorization required.\nOpen {s} and enter code: {s}\nWaiting for you to approve in the browser...\n",
        .{ host.label(), verification_uri, user_code },
    );
    openBrowser(allocator, io, verification_uri);

    var req2: std.Io.Writer.Allocating = .init(allocator);
    defer req2.deinit();
    try req2.writer.writeAll("client_id=");
    try (std.Uri.Component{ .raw = client_id }).formatQuery(&req2.writer);
    try req2.writer.writeAll("&device_code=");
    try (std.Uri.Component{ .raw = device_code }).formatQuery(&req2.writer);
    try req2.writer.writeAll("&grant_type=urn:ietf:params:oauth:grant-type:device_code");
    const poll_body = req2.written();

    var elapsed: i64 = 0;
    while (elapsed < expires_in) {
        try std.Io.sleep(io, .fromSeconds(interval_secs), .real);
        elapsed += interval_secs;

        const token_resp = try postForm(allocator, &client, ep.token_url, poll_body);
        const token_parsed = std.json.parseFromSlice(std.json.Value, allocator, token_resp, .{}) catch continue;
        defer token_parsed.deinit();
        if (token_parsed.value != .object) continue;
        const to = token_parsed.value.object;

        if (forge.jsonStr(to, "access_token")) |tok| {
            std.debug.print("{s} authorized.\n", .{host.label()});
            return try allocator.dupe(u8, tok);
        }

        if (forge.jsonStr(to, "error")) |e| {
            if (std.mem.eql(u8, e, "authorization_pending")) continue;
            if (std.mem.eql(u8, e, "slow_down")) {
                interval_secs += 5;
                continue;
            }
            return error.DeviceFlowDenied; // expired_token, access_denied, or another terminal error
        }
    }
    return error.DeviceFlowTimedOut;
}
