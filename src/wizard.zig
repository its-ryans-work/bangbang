const std = @import("std");
const forge = @import("forge.zig");
const auth = @import("auth.zig");
const sysinfo = @import("sysinfo.zig");

fn markerPath(allocator: std.mem.Allocator, environ: *const std.process.Environ.Map) ![]const u8 {
    const dir = try auth.cacheDir(allocator, environ);
    return std.fmt.allocPrint(allocator, "{s}/init_done", .{dir});
}

/// True unless the first-run marker file already exists (or its path can't
/// be determined, e.g. no HOME -- treated as "don't offer" rather than
/// erroring, since this is only ever an optional convenience prompt).
pub fn shouldOfferFirstRun(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) bool {
    const path = markerPath(allocator, environ) catch return false;
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return true;
    return false;
}

pub fn markDone(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) !void {
    const dir = try auth.cacheDir(allocator, environ);
    try std.Io.Dir.cwd().createDirPath(io, dir);
    const path = try markerPath(allocator, environ);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "" });
}

fn displayName(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "GitHub",
        .gitlab => "GitLab",
        .codeberg => "Codeberg",
        .exploitdb => "ExploitDB", // unused: exploitdb needs no auth setup, the wizard's host list never includes it
    };
}

/// Where a manual CLI install lives, for OSes/hosts sysinfo.zig doesn't know
/// how to install through automatically yet.
fn cliInstallUrl(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "https://cli.github.com/",
        .gitlab => "https://gitlab.com/gitlab-org/cli#installation",
        .codeberg => "https://gitea.com/gitea/tea", // unused: codeberg's flow never reaches this
        .exploitdb => "https://gitlab.com/exploit-database/exploitdb", // unused: see displayName
    };
}

fn patSettingsUrl(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "https://github.com/settings/tokens/new",
        .gitlab => "https://gitlab.com/-/user_settings/personal_access_tokens",
        .codeberg => "https://codeberg.org/user/settings/applications",
        .exploitdb => "", // unused: see displayName
    };
}

/// Where to go to see/revoke *existing* tokens -- distinct from
/// `patSettingsUrl` for GitHub (whose "/new" page is create-only); GitLab and
/// Codeberg show existing + create on the same page either way.
fn patManageUrl(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "https://github.com/settings/tokens",
        .gitlab => "https://gitlab.com/-/user_settings/personal_access_tokens",
        .codeberg => "https://codeberg.org/user/settings/applications",
        .exploitdb => "", // unused: see displayName
    };
}

fn patScopeHint(host: forge.Host) []const u8 {
    return switch (host) {
        .github => "select the \"public_repo\" scope (or \"repo\" if you also want private repos)",
        .gitlab => "select the \"read_api\" scope",
        .codeberg => "read-only repository access is enough",
        .exploitdb => "", // unused: see displayName
    };
}

const HostStatus = struct {
    env_token: bool,
    persisted_token: bool,
    cli_installed: bool,
    cli_authenticated: bool,

    fn isGood(self: HostStatus) bool {
        return self.env_token or self.persisted_token or self.cli_authenticated;
    }
};

fn checkStatus(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map, host: forge.Host) HostStatus {
    const env_token = blk: {
        const v = environ.get(auth.tokenVarFor(host)) orelse break :blk false;
        break :blk v.len > 0;
    };
    const persisted_token = (auth.loadCachedToken(allocator, io, environ, host) catch null) != null;

    var cli_installed = false;
    var cli_authenticated = false;
    if (host != .codeberg) { // codeberg has no CLI we drive
        const bin = host.label();
        cli_installed = auth.probeCli(allocator, io, bin);
        if (cli_installed) cli_authenticated = auth.cliAuthenticated(allocator, io, bin);
    }

    return .{
        .env_token = env_token,
        .persisted_token = persisted_token,
        .cli_installed = cli_installed,
        .cli_authenticated = cli_authenticated,
    };
}

/// Runs `argv` with stdio *inherited* from the parent (unlike
/// std.process.run, used everywhere else in this codebase, which always
/// captures output) -- confirmed live that std.process.spawn's default
/// StdIo.inherit genuinely passes both directions through, which is what an
/// interactive `brew install`/`gh auth login` needs: the user has to see the
/// real prompts and be able to type into them.
fn runInteractive(io: std.Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{ .argv = argv }) catch return false;
    const term = child.wait(io) catch return false;
    return forge.termOk(term);
}

fn readChoice(in: *std.Io.Reader) u8 {
    const line = (in.takeDelimiter('\n') catch null) orelse return 0;
    const t = std.mem.trim(u8, line, " \t\r");
    return if (t.len == 0) 0 else t[0];
}

fn promptForToken(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
) !void {
    const url = patSettingsUrl(host);
    try out.print("\n  opening {s}\n  ({s})\n", .{ url, patScopeHint(host) });
    try out.flush();
    auth.openBrowser(allocator, io, url);

    try out.writeAll("  paste the token here (input is not masked/hidden) and press enter, or leave blank to skip: ");
    try out.flush();
    const line = (in.takeDelimiter('\n') catch null) orelse return;
    const token = std.mem.trim(u8, line, " \t\r");
    if (token.len == 0) {
        try out.writeAll("  skipped.\n");
        return;
    }
    try auth.saveCachedToken(allocator, io, environ, host, token);
    try out.print("  saved -- {s} will use this automatically from now on.\n", .{displayName(host)});
}

fn reportCliOutcome(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, host: forge.Host) !void {
    if (auth.cliAuthenticated(allocator, io, host.label())) {
        try out.print("  {s} is now authenticated.\n", .{displayName(host)});
    } else {
        try out.print("  still not authenticated -- you can try again any time with `bangbang --init`.\n", .{});
    }
}

fn handleGithubOrGitlab(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
    status: HostStatus,
) !void {
    const bin = host.label();

    if (!status.cli_installed) {
        const pm = sysinfo.detectPackageManager(allocator, io);
        if (pm == .homebrew) {
            try out.print("  [1] install {s} via Homebrew, then log in\n", .{bin});
        } else {
            try out.print("  ({s} CLI not found -- manual install: {s})\n", .{ bin, cliInstallUrl(host) });
        }
        try out.writeAll("  [2] paste a personal access token\n  [3] skip\n  > ");
        try out.flush();

        switch (readChoice(in)) {
            '1' => {
                if (pm == .homebrew) {
                    try out.print("  installing {s} via Homebrew...\n", .{bin});
                    try out.flush();
                    if (runInteractive(io, &.{ "brew", "install", bin })) {
                        try out.print("  installed. running `{s} auth login`...\n", .{bin});
                        try out.flush();
                        _ = runInteractive(io, &.{ bin, "auth", "login" });
                        try reportCliOutcome(allocator, io, out, host);
                    } else {
                        try out.writeAll("  install failed -- see output above. you can also paste a token instead (`bangbang --init`).\n");
                    }
                } else {
                    try promptForToken(allocator, io, out, in, environ, host);
                }
            },
            '2' => try promptForToken(allocator, io, out, in, environ, host),
            else => try out.writeAll("  skipped.\n"),
        }
        return;
    }

    // CLI installed but not authenticated.
    try out.print("  [1] run `{s} auth login` now (opens your browser)\n  [2] paste a personal access token\n  [3] skip\n  > ", .{bin});
    try out.flush();
    switch (readChoice(in)) {
        '1' => {
            _ = runInteractive(io, &.{ bin, "auth", "login" });
            try reportCliOutcome(allocator, io, out, host);
        },
        '2' => try promptForToken(allocator, io, out, in, environ, host),
        else => try out.writeAll("  skipped.\n"),
    }
}

fn handleCodeberg(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    environ: *const std.process.Environ.Map,
) !void {
    try out.writeAll("  Codeberg has no CLI with a browser-login flow we can drive (see notes below).\n");
    try promptForToken(allocator, io, out, in, environ, .codeberg);

    if (!sysinfo.binExists(allocator, io, "tea")) {
        try out.writeAll(
            "  (aside: `tea`, the official Gitea/Forgejo CLI, works with Codeberg too if you'd like a\n" ++
                "   general-purpose one for outside this tool -- it still needs a token, same as above,\n" ++
                "   it doesn't do browser login either. `brew install tea` if you want it; not required\n" ++
                "   for bangbang itself.)\n",
        );
    }
}

fn handleHost(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    environ: *const std.process.Environ.Map,
    host: forge.Host,
) !void {
    const status = checkStatus(allocator, io, environ, host);
    try out.print("\n[{s}]\n", .{displayName(host)});

    if (status.env_token) {
        try out.print("  {s} is set -- good, using that.\n", .{auth.tokenVarFor(host)});
        return;
    }
    if (status.cli_authenticated) {
        try out.print("  {s} CLI is installed and authenticated -- good.\n", .{host.label()});
        return;
    }
    if (status.persisted_token) {
        try out.writeAll("  a saved token is already configured -- good.\n");
        return;
    }

    try out.writeAll("  not set up yet -- requests will be rate-limited.\n");
    switch (host) {
        .github, .gitlab => try handleGithubOrGitlab(allocator, io, out, in, environ, host, status),
        .codeberg => try handleCodeberg(allocator, io, out, in, environ),
        // Never reached: exploitdb needs no auth, and every caller iterates
        // an explicit {github, gitlab, codeberg} list rather than all of
        // forge.Host -- this arm exists only to satisfy the exhaustive switch.
        .exploitdb => {},
    }
}

/// Interactive setup flow: detects OS/package manager, then walks through
/// each host's auth status and offers to fix whatever's missing. `out`/`in`
/// are the caller's shared stdout/stdin (see `ui.run`'s doc comment for why
/// this isn't constructed locally).
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    environ: *const std.process.Environ.Map,
) !void {
    const os = sysinfo.detectOs();
    const pm = sysinfo.detectPackageManager(allocator, io);
    try out.print("bangbang setup wizard\nsystem: {s}\npackage manager: {s}\n", .{ sysinfo.label(os), pm.label() });
    try out.flush();

    for ([_]forge.Host{ .github, .gitlab, .codeberg }) |host| {
        try handleHost(allocator, io, out, in, environ, host);
        try out.flush();
    }

    try out.writeAll("\nsetup complete -- re-run any time with `bangbang --init`.\n");
    try out.flush();
    try markDone(allocator, io, environ);
}

/// Deletes every locally-cached token bangbang has stored (nothing else --
/// env vars were never written by us and aren't touched; an authenticated
/// `gh`/`glab` CLI keeps its own separate credential storage untouched too).
/// Always prints the disclaimer: this cannot and does not revoke anything on
/// GitHub/GitLab/Codeberg's own side.
pub fn deleteTokens(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    environ: *const std.process.Environ.Map,
) !void {
    var any_deleted = false;
    for ([_]forge.Host{ .github, .gitlab, .codeberg }) |host| {
        const deleted = auth.deleteCachedToken(allocator, io, environ, host) catch |err| {
            try out.print("  {s}: could not delete ({s})\n", .{ displayName(host), @errorName(err) });
            continue;
        };
        if (deleted) {
            any_deleted = true;
            try out.print("  {s}: deleted the locally-cached token\n", .{displayName(host)});
        } else {
            try out.print("  {s}: no locally-cached token found\n", .{displayName(host)});
        }
    }

    if (any_deleted) {
        try out.writeAll(
            \\
            \\Note: this only removed tokens bangbang cached on THIS machine's local disk. It has
            \\no way to revoke them on GitHub/GitLab/Codeberg's own side -- if you want a token
            \\fully invalidated (e.g. it may have leaked, or you're done with it for good), go
            \\revoke/delete it yourself from each platform's own settings:
            \\
        );
        for ([_]forge.Host{ .github, .gitlab, .codeberg }) |host| {
            try out.print("  {s}: {s}\n", .{ displayName(host), patManageUrl(host) });
        }
    } else {
        try out.writeAll("\nnothing to delete -- no locally-cached tokens were found.\n");
    }
    try out.flush();
}

test "HostStatus.isGood" {
    try std.testing.expect((HostStatus{ .env_token = true, .persisted_token = false, .cli_installed = false, .cli_authenticated = false }).isGood());
    try std.testing.expect((HostStatus{ .env_token = false, .persisted_token = true, .cli_installed = false, .cli_authenticated = false }).isGood());
    try std.testing.expect((HostStatus{ .env_token = false, .persisted_token = false, .cli_installed = true, .cli_authenticated = true }).isGood());
    try std.testing.expect(!(HostStatus{ .env_token = false, .persisted_token = false, .cli_installed = true, .cli_authenticated = false }).isGood());
    try std.testing.expect(!(HostStatus{ .env_token = false, .persisted_token = false, .cli_installed = false, .cli_authenticated = false }).isGood());
}
