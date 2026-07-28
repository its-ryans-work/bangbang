const std = @import("std");
const build_options = @import("build_options");
const cve = @import("cve.zig");
const nvd = @import("nvd.zig");
const forge = @import("forge.zig");
const auth = @import("auth.zig");
const github = @import("github.zig");
const gitlab = @import("gitlab.zig");
const codeberg = @import("codeberg.zig");
const exploitdb = @import("exploitdb.zig");
const filter = @import("filter.zig");
const color = @import("color.zig");
const ui = @import("ui.zig");
const wizard = @import("wizard.zig");

const Config = struct {
    max_cves: usize = 0, // 0 = unlimited (bounded only by nvd.safety_cap)
    max_hits: usize = 5,
    threshold: usize = filter.default_threshold,
    show_all: bool = false,
    nvd_api_key: ?[]const u8 = null,
    query: []const u8 = "",
    run_init: bool = false,
    delete_tokens: bool = false,
    sources: std.EnumSet(forge.Host) = .initFull(),
    download_dir: ?[]const u8 = null, // null = ui.zig's own default ("./bangbang-downloads")
};

fn parseArgs(allocator: std.mem.Allocator, args: []const [:0]const u8, environ: *const std.process.Environ.Map) !Config {
    var cfg: Config = .{ .nvd_api_key = environ.get("NVD_API_KEY") };

    var query_parts: std.ArrayList([]const u8) = .empty;
    defer query_parts.deinit(allocator);

    var i: usize = 1; // skip argv[0]
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--max-cves")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.max_cves = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--max-hits")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.max_hits = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--threshold")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.threshold = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, a, "--show-all")) {
            cfg.show_all = true;
        } else if (std.mem.eql(u8, a, "--nvd-api-key")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.nvd_api_key = args[i];
        } else if (std.mem.eql(u8, a, "--init")) {
            cfg.run_init = true;
        } else if (std.mem.eql(u8, a, "--delete-tokens")) {
            cfg.delete_tokens = true;
        } else if (std.mem.eql(u8, a, "--dir")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.download_dir = args[i];
        } else if (std.mem.eql(u8, a, "--sources")) {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            cfg.sources = .initEmpty();
            var it = std.mem.tokenizeScalar(u8, args[i], ',');
            while (it.next()) |tok| {
                const host = forge.Host.fromLabel(tok) orelse return error.UnknownSource;
                cfg.sources.insert(host);
            }
            if (cfg.sources.count() == 0) return error.UnknownSource;
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            return error.ShowHelp;
        } else if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-v")) {
            return error.ShowVersion;
        } else {
            try query_parts.append(allocator, a);
        }
    }

    cfg.query = try std.mem.join(allocator, " ", query_parts.items);
    return cfg;
}

fn printUsage(out: *std.Io.Writer, prog: []const u8) !void {
    try out.print(
        \\usage: {s} [options] <keyword|CVE-ID>
        \\       {s} --init
        \\       {s} --delete-tokens
        \\
        \\  --init             run the interactive auth setup wizard (also offered automatically
        \\                     on first run) and exit
        \\  --delete-tokens    delete any tokens bangbang has cached locally on this machine, and exit
        \\                     (does NOT revoke them on GitHub/GitLab/Codeberg's side -- local disk only)
        \\  --max-cves N       max CVEs to pivot on (default: unlimited -- every match NVD has,
        \\                     capped only at {d} as a backstop)
        \\  --max-hits N       max repo hits fetched per CVE per host (default 5)
        \\  --threshold N      hide repos mentioning >= N distinct CVEs as list-dumps (default {d})
        \\  --show-all         don't hide anything, just flag it
        \\  --dir PATH         download directory (default ./bangbang-downloads); can still be
        \\                     changed later with the `dir` command inside the REPL
        \\  --nvd-api-key KEY  NVD API key (raises the keyword-search rate limit); also read from NVD_API_KEY
        \\  --sources LIST     comma-separated hosts to search: gh, glab, cb, edb
        \\                     (or github/gitlab/codeberg/exploitdb; default: all four). Useful after a
        \\                     run reports a host as rate-limited -- rerun with just the others, or just
        \\                     the limited one(s) once it resets.
        \\  -h, --help         this message
        \\  -v, --version      print the version and exit
        \\
        \\searches github, gitlab, codeberg, and exploit-db for each CVE. exploit-db needs no auth or
        \\live API calls -- its exploit database is cached locally (~10MB) after the first run. If a
        \\keyword search turns up zero repo hits across every CVE found, you'll be offered a broader
        \\"<keyword> CVE" search across github/gitlab/codeberg as a fallback. If any host looks
        \\rate-limited during a run, you'll see a warning at the end -- those results may be incomplete.
        \\
        \\auth: GITHUB_TOKEN / GITLAB_TOKEN / CODEBERG_TOKEN env vars, an authenticated `gh`/`glab`
        \\CLI, or a saved token from `--init` are used automatically if present. Without any of
        \\those, set BANGBANG_GITHUB_CLIENT_ID / BANGBANG_GITLAB_CLIENT_ID to enable browser login
        \\for those two, or it falls back to slower unauthenticated requests.
        \\
    , .{ prog, prog, prog, nvd.safety_cap, filter.default_threshold });
}

/// Each of these runs one host's full "search, then fetch every readme"
/// pipeline, meant to be dispatched via `std.Io.async` so all three hosts
/// run concurrently instead of one after another. Deliberately still fully
/// serial *within* one host (search, then each readme fetch in turn) --
/// GitHub's own API guidance warns that firing concurrent requests at one
/// host can trip its abuse-detection layer even under the numeric rate
/// limit, so cross-host parallelism is the whole extent of it: at most one
/// request is ever in flight to any single host at a time.
///
/// Each task gets its own arena backed by `std.heap.page_allocator` rather
/// than the caller's shared arena, since `std.heap.ArenaAllocator` isn't
/// safe to use from more than one thread at once. That arena is
/// deliberately never deinit'd -- page_allocator is thread-safe and not
/// leak-tracked (unlike the debug gpa), and it's the same backing allocator
/// and never-individually-freed lifetime the program's own top-level arena
/// already uses, so the returned hits stay valid for the rest of the run
/// without a fragile per-field copy back into the shared arena.
fn fetchGithubHits(io: std.Io, mode: auth.AuthMode, id: cve.CveId, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try github.searchCve(a, io, mode, id, per_page);
    for (result.hits) |*h| github.fetchReadme(a, io, mode, h);
    return result;
}

fn fetchGitlabHits(io: std.Io, mode: auth.AuthMode, id: cve.CveId, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try gitlab.searchCve(a, io, mode, id, per_page);
    for (result.hits) |*h| gitlab.fetchReadme(a, io, mode, h);
    return result;
}

fn fetchCodebergHits(io: std.Io, mode: auth.AuthMode, id: cve.CveId, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try codeberg.searchCve(a, io, mode, id, per_page);
    for (result.hits) |*h| codeberg.fetchReadme(a, io, mode, h);
    return result;
}

/// Same shape as the other three, but the "search" step is a purely local
/// hash-map lookup (the CSV is already loaded/parsed) -- it can never be
/// rate-limited, only the per-hit readme (raw exploit source) fetches touch
/// the network. `db` is null when --sources excluded exploitdb or the CSV
/// failed to load; either way this just contributes zero hits.
fn fetchExploitdbHits(io: std.Io, db: ?*const exploitdb.Database, id: cve.CveId, max_results: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    const database = db orelse return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try exploitdb.searchCve(a, database, id, max_results);
    for (result.hits) |*h| exploitdb.fetchReadme(a, io, h);
    return result;
}

fn buildGroup(
    allocator: std.mem.Allocator,
    io: std.Io,
    gh_mode: auth.AuthMode,
    gl_mode: auth.AuthMode,
    cb_mode: auth.AuthMode,
    edb_db: ?*const exploitdb.Database,
    match: nvd.CveMatch,
    max_hits: usize,
    threshold: usize,
    sources: std.EnumSet(forge.Host),
) !forge.CveGroup {
    // Over-fetch relative to max_hits so dropping dump-flagged hits still
    // leaves close to max_hits good results per host.
    const per_page = max_hits * 3;

    // std.Io.async never errors -- if no worker thread is free it just runs
    // the task inline instead, so this degrades gracefully to the old fully
    // sequential behavior under load rather than failing. A host excluded
    // via --sources still gets dispatched (cheap: the task itself no-ops
    // immediately) rather than special-cased here, to avoid the awkwardness
    // of an optional Future.
    var gh_future = std.Io.async(io, fetchGithubHits, .{ io, gh_mode, match.id, per_page, sources.contains(.github) });
    var gl_future = std.Io.async(io, fetchGitlabHits, .{ io, gl_mode, match.id, per_page, sources.contains(.gitlab) });
    var cb_future = std.Io.async(io, fetchCodebergHits, .{ io, cb_mode, match.id, per_page, sources.contains(.codeberg) });
    var edb_future = std.Io.async(io, fetchExploitdbHits, .{ io, edb_db, match.id, per_page, sources.contains(.exploitdb) });

    const gh_result = try gh_future.await(io);
    const gl_result = try gl_future.await(io);
    const cb_result = try cb_future.await(io);
    const edb_result = try edb_future.await(io);

    var rate_limited: std.EnumSet(forge.Host) = .initEmpty();
    if (gh_result.rate_limited) rate_limited.insert(.github);
    if (gl_result.rate_limited) rate_limited.insert(.gitlab);
    if (cb_result.rate_limited) rate_limited.insert(.codeberg);
    if (edb_result.rate_limited) rate_limited.insert(.exploitdb);

    const total = gh_result.hits.len + gl_result.hits.len + cb_result.hits.len + edb_result.hits.len;
    const merged = try allocator.alloc(forge.RepoHit, total);
    var off: usize = 0;
    @memcpy(merged[off..][0..gh_result.hits.len], gh_result.hits);
    off += gh_result.hits.len;
    @memcpy(merged[off..][0..gl_result.hits.len], gl_result.hits);
    off += gl_result.hits.len;
    @memcpy(merged[off..][0..cb_result.hits.len], cb_result.hits);
    off += cb_result.hits.len;
    @memcpy(merged[off..][0..edb_result.hits.len], edb_result.hits);

    try filter.annotate(allocator, merged, threshold);

    const label = try match.id.allocString(allocator);
    return .{ .display_label = label, .dir_name = label, .hits = merged, .cvss = match.cvss, .rate_limited = rate_limited };
}

/// Renders `sources` as a "+"-joined list of host labels, e.g.
/// "gh + glab + cb + edb" -- used in the per-CVE hunting status line so it
/// accurately reflects a --sources-narrowed run instead of always naming
/// all four.
fn writeSourceList(out: *std.Io.Writer, sources: std.EnumSet(forge.Host)) !void {
    var first = true;
    var it = sources.iterator();
    while (it.next()) |h| {
        if (!first) try out.writeAll(" + ");
        first = false;
        try out.writeAll(h.label());
    }
}

fn mostSevere(matches: []const nvd.CveMatch) cve.Severity {
    var best: cve.Severity = .none;
    for (matches) |m| {
        if (m.cvss.severity.rank() > best.rank()) best = m.cvss.severity;
    }
    return best;
}

/// Prints the "N CVE(s) Found!" summary line, colored by the single most
/// severe CVE in the batch, on its own line, then a blank line, then the
/// "Newest first:" enumeration -- each CVE id plain, with just its own
/// score (not the whole id) colored by its own severity.
fn printSummary(out: *std.Io.Writer, c: color.Colors, matches: []const nvd.CveMatch) !void {
    const overall = c.forSeverity(mostSevere(matches));
    try out.print("\n{s}{d} CVE(s) Found!{s}\n\nNewest first:", .{ overall, matches.len, c.reset });
    for (matches) |m| {
        var id_buf: [16]u8 = undefined;
        const id_str = try m.id.toSlice(&id_buf);
        var score_buf: [8]u8 = undefined;
        const score_str = try color.formatScore(m.cvss.score, &score_buf);
        try out.print(" {s}({s}{s}{s})", .{ id_str, c.forSeverity(m.cvss.severity), score_str, c.reset });
    }
    try out.writeAll("\n");
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buf);
    const out = &stdout_writer.interface;

    var stdin_buf: [4096]u8 = undefined;
    var stdin_reader: std.Io.File.Reader = .init(.stdin(), io, &stdin_buf);
    const in = &stdin_reader.interface;

    const args = try init.minimal.args.toSlice(allocator);
    const prog = if (args.len > 0) args[0] else "bangbang";

    const cfg = parseArgs(allocator, args, init.environ_map) catch |err| {
        if (err == error.ShowVersion) {
            try out.print("bangbang {s}\n", .{build_options.version});
            try out.flush();
            return;
        }
        try printUsage(out, prog);
        try out.flush();
        if (err == error.ShowHelp) return;
        return err;
    };

    if (cfg.run_init) {
        try wizard.run(allocator, io, out, in, init.environ_map);
        return;
    }

    if (cfg.delete_tokens) {
        try wizard.deleteTokens(allocator, io, out, init.environ_map);
        return;
    }

    if (cfg.query.len == 0) {
        try printUsage(out, prog);
        try out.flush();
        return;
    }

    const stdin_is_tty = std.Io.File.stdin().isTty(io) catch false;
    if (stdin_is_tty and wizard.shouldOfferFirstRun(allocator, io, init.environ_map)) {
        try out.writeAll("first run: set up GitHub/GitLab/Codeberg auth now to avoid rate limits? [Y/n] ");
        try out.flush();
        const line = (in.takeDelimiter('\n') catch null) orelse "";
        const answer = std.mem.trim(u8, line, " \t\r");
        if (answer.len == 0 or answer[0] == 'y' or answer[0] == 'Y') {
            try wizard.run(allocator, io, out, in, init.environ_map);
            try out.writeAll("\n");
        } else {
            try wizard.markDone(allocator, io, init.environ_map);
            try out.writeAll("skipping -- run `bangbang --init` any time to revisit this.\n");
        }
    }

    const c = color.detectColors(io);

    var cve_matches: []const nvd.CveMatch = undefined;
    var is_keyword_search: bool = undefined;
    if (cve.parseExact(cfg.query)) |literal| {
        is_keyword_search = false;
        // CVSS enrichment is best-effort here -- an unknown-to-NVD id (typo,
        // too new to be indexed yet) or a network hiccup still hunts for the
        // literal CVE on github/gitlab/codeberg, just without a score.
        const looked_up = nvd.fetchById(allocator, io, literal, cfg.nvd_api_key) catch null;
        const single = looked_up orelse nvd.CveMatch{ .id = literal };
        cve_matches = try allocator.dupe(nvd.CveMatch, &.{single});
    } else {
        is_keyword_search = true;
        try out.print("searching NVD for \"{s}\"...\n", .{cfg.query});
        try out.flush();
        const all = nvd.search(allocator, io, cfg.query, cfg.nvd_api_key) catch |err| {
            try out.print("NVD search failed: {s}\n", .{@errorName(err)});
            try out.flush();
            return err;
        };
        if (all.len == 0) {
            try out.print("no CVEs matched \"{s}\"\n", .{cfg.query});
            try out.flush();
            return;
        }
        cve_matches = if (cfg.max_cves == 0) all else all[0..@min(all.len, cfg.max_cves)];
    }

    try printSummary(out, c, cve_matches);
    try out.flush();

    // Skip auth resolution entirely for a host excluded via --sources -- no
    // point spawning `gh auth status`/etc. or printing a "no auth
    // configured" notice for a host that's never going to be queried.
    const gh_mode: auth.AuthMode = if (cfg.sources.contains(.github)) try auth.resolve(allocator, io, init.environ_map, .github) else .none;
    const gl_mode: auth.AuthMode = if (cfg.sources.contains(.gitlab)) try auth.resolve(allocator, io, init.environ_map, .gitlab) else .none;
    const cb_mode: auth.AuthMode = if (cfg.sources.contains(.codeberg)) try auth.resolve(allocator, io, init.environ_map, .codeberg) else .none;

    // No auth exists for exploitdb at all -- just the CSV database, loaded
    // once up front (cached locally after the first run) rather than
    // per-CVE. Non-fatal on failure: warn and treat it as zero hits for the
    // rest of this run, same as any other source failing.
    var edb_db_storage: ?exploitdb.Database = if (cfg.sources.contains(.exploitdb))
        exploitdb.load(allocator, io, out, init.environ_map) catch |err| blk: {
            std.debug.print("warn: exploitdb: could not load exploit database: {s}\n", .{@errorName(err)});
            break :blk null;
        }
    else
        null;
    const edb_db: ?*const exploitdb.Database = if (edb_db_storage) |*db| db else null;

    // TTY-gated the same way colors are: overwriting the status line in
    // place with \r + erase-to-end-of-line only makes sense on a real
    // terminal -- piped/redirected output keeps one line per CVE.
    const stdout_tty = color.stdoutIsTty(io);

    var source_list_buf: std.Io.Writer.Allocating = .init(allocator);
    try writeSourceList(&source_list_buf.writer, cfg.sources);
    const source_list = source_list_buf.written();

    const groups = try allocator.alloc(forge.CveGroup, cve_matches.len);
    var rate_limited: std.EnumSet(forge.Host) = .initEmpty();
    for (cve_matches, 0..) |m, i| {
        var cve_buf: [16]u8 = undefined;
        const id_str = try m.id.toSlice(&cve_buf);
        if (stdout_tty) {
            try out.print("\r\x1b[Khunting PoCs for {s} on {s}...", .{ id_str, source_list });
        } else {
            try out.print("hunting PoCs for {s} on {s}...\n", .{ id_str, source_list });
        }
        try out.flush();
        groups[i] = try buildGroup(allocator, io, gh_mode, gl_mode, cb_mode, edb_db, m, cfg.max_hits, cfg.threshold, cfg.sources);
        rate_limited.setUnion(groups[i].rate_limited);
    }
    if (stdout_tty) try out.writeAll("\n");
    try printRateLimitWarning(out, c, rate_limited);
    try out.flush();

    var opts: ui.Options = .{
        .show_all = cfg.show_all,
        .gh_mode = gh_mode,
        .gl_mode = gl_mode,
        .cb_mode = cb_mode,
        .edb_db = edb_db,
        .threshold = cfg.threshold,
        .max_hits = cfg.max_hits,
        .fallback_query = if (is_keyword_search) cfg.query else null,
        .fallback_per_page = cfg.max_hits * 3,
        .sources = cfg.sources,
    };
    if (cfg.download_dir) |d| opts.default_download_dir = d;

    try ui.run(allocator, io, out, in, groups, opts);
}

/// Prints one aggregated warning if any host looked rate-limited at any
/// point during the run, so incomplete results aren't mistaken for a clean
/// "nothing there." Deliberately doesn't presume which direction the user
/// wants to go with `--sources` on a retry (skip the limited host(s), or
/// target just them once the limit resets) -- just names them and points at
/// the flag.
fn printRateLimitWarning(out: *std.Io.Writer, c: color.Colors, limited: std.EnumSet(forge.Host)) !void {
    if (limited.count() == 0) return;
    try out.print("\n{s}warning:{s} rate-limited by ", .{ c.yellow, c.reset });
    var first = true;
    var it = limited.iterator();
    while (it.next()) |h| {
        if (!first) try out.writeAll(", ");
        first = false;
        try out.print("{s}", .{h.label()});
    }
    try out.writeAll(" -- results from those host(s) may be incomplete. Use --sources to target specific hosts on a re-run.\n");
}
