const std = @import("std");
const cve = @import("cve.zig");
const forge = @import("forge.zig");
const auth = @import("auth.zig");
const filter = @import("filter.zig");
const download = @import("download.zig");
const github = @import("github.zig");
const gitlab = @import("gitlab.zig");
const codeberg = @import("codeberg.zig");
const exploitdb = @import("exploitdb.zig");
const color = @import("color.zig");

/// One hit plus its persistent selection state. Lives in a stable,
/// never-rebuilt array per CVE group so selection survives a show-all /
/// hide-dumps toggle (which only changes what's *visible*, addressed
/// separately -- see `buildVisible`).
const HitEntry = struct {
    hit: forge.RepoHit,
    selected: bool = false,
};

const Group = struct {
    display_label: []const u8,
    dir_name: []const u8,
    all: []HitEntry, // fixed order (stars desc), set once; includes dump-flagged hits
    cvss: cve.Cvss = .{}, // .none/null for the generic-fallback-search group, which isn't tied to one CVE
};

pub const Options = struct {
    show_all: bool,
    gh_mode: auth.AuthMode,
    gl_mode: auth.AuthMode,
    cb_mode: auth.AuthMode,
    edb_db: ?*const exploitdb.Database = null,
    threshold: usize,
    max_hits: usize = 5,
    default_download_dir: []const u8 = "./bangbang-downloads",
    /// Set to the original search keyword when the run was a keyword search
    /// (not a literal CVE ID) -- enables the zero-hits fallback offer. null
    /// disables the feature entirely (e.g. for a literal-CVE-ID run, where
    /// "<CVE-ID> CVE" wouldn't add anything).
    fallback_query: ?[]const u8 = null,
    fallback_per_page: usize = 15,
    sources: std.EnumSet(forge.Host) = .initFull(),
};

fn starsDesc(_: void, a: forge.RepoHit, b: forge.RepoHit) bool {
    return a.stars > b.stars;
}

fn toGroup(allocator: std.mem.Allocator, g: forge.CveGroup) !Group {
    std.sort.pdq(forge.RepoHit, g.hits, {}, starsDesc);
    const entries = try allocator.alloc(HitEntry, g.hits.len);
    for (g.hits, 0..) |h, i| entries[i] = .{ .hit = h };
    return .{ .display_label = g.display_label, .dir_name = g.dir_name, .all = entries, .cvss = g.cvss };
}

fn buildGroups(allocator: std.mem.Allocator, raw: []forge.CveGroup) !std.ArrayList(Group) {
    var groups: std.ArrayList(Group) = .empty;
    for (raw) |g| try groups.append(allocator, try toGroup(allocator, g));
    return groups;
}

fn totalHits(groups: []const Group) usize {
    var n: usize = 0;
    for (groups) |g| n += g.all.len;
    return n;
}

// forge.Host's variant count (github, gitlab, codeberg, exploitdb) -- used
// to size the per-host counters in buildVisible below. Bump this if
// forge.Host ever grows a 5th host.
const host_count = 4;

/// Per group, the indices into `.all` that are currently visible, in display
/// order -- recomputed only when show-all/hide-dumps toggles (or a group is
/// added, e.g. by the zero-hits fallback search).
///
/// Dump-flagged hits are hidden unless `show_all`, same as before. On top of
/// that, each host is capped at `max_hits` non-dump hits when `!show_all` --
/// `--max-hits` previously only controlled how many candidates were
/// *fetched* (over-fetched 3x, actually, to leave headroom for dump
/// filtering), with nothing ever trimming the surviving non-dump hits back
/// down, so a popular CVE could show far more than `--max-hits` per host.
/// `g.all` is already sorted stars-descending (see `toGroup`), so the first
/// `max_hits` non-dump entries encountered per host here are the right ones
/// to keep. `show_all` reveals both dump-flagged hits and anything the cap
/// would otherwise hide, same toggle as before.
fn buildVisible(allocator: std.mem.Allocator, groups: []const Group, show_all: bool, max_hits: usize) ![][]usize {
    var result: std.ArrayList([]usize) = .empty;
    defer result.deinit(allocator);

    for (groups) |g| {
        var idxs: std.ArrayList(usize) = .empty;
        defer idxs.deinit(allocator);
        var per_host_shown = [_]usize{0} ** host_count;
        for (g.all, 0..) |entry, i| {
            if (entry.hit.is_dump) {
                if (!show_all) continue;
                try idxs.append(allocator, i);
                continue;
            }
            const host_idx = @intFromEnum(entry.hit.host);
            if (!show_all and per_host_shown[host_idx] >= max_hits) continue;
            per_host_shown[host_idx] += 1;
            try idxs.append(allocator, i);
        }
        try result.append(allocator, try idxs.toOwnedSlice(allocator));
    }
    return try result.toOwnedSlice(allocator);
}

fn countDumps(all: []const HitEntry) usize {
    var n: usize = 0;
    for (all) |e| {
        if (e.hit.is_dump) n += 1;
    }
    return n;
}

fn renderHit(out: *std.Io.Writer, c: color.Colors, e: HitEntry, gi: usize, hi: usize) !void {
    const mark_color = if (e.selected) c.green else "";
    const mark: u8 = if (e.selected) 'x' else ' ';
    try out.print("  [{s}{c}{s}] {d}.{d}  {s}{s}{s}  {s}{s}{s}  {s}\xe2\x98\x85{d}{s}  {s}", .{
        mark_color, mark, c.reset,
        gi,          hi,
        c.dim,       e.hit.host.label(), c.reset,
        c.bold,      e.hit.full_name,    c.reset,
        c.yellow,    e.hit.stars,        c.reset,
        e.hit.description,
    });
    if (e.hit.is_dump) try out.print("  {s}[dump-flagged]{s}", .{ c.red, c.reset });
    try out.writeAll("\n");

    const created = if (e.hit.created_at.len > 0) e.hit.created_at else "unknown";
    try out.print("        {s}forks:{d}  created:{s}  {s}", .{ c.dim, e.hit.forks, created, e.hit.repo_url });
    if (e.hit.owner_url.len > 0) try out.print("  (author: {s})", .{e.hit.owner_url});
    try out.print("{s}\n", .{c.reset});
}

fn renderAll(out: *std.Io.Writer, c: color.Colors, groups: []const Group, visible: []const []usize) !void {
    for (groups, 0..) |g, gi_0| {
        const gi = gi_0 + 1;
        const idxs = visible[gi_0];
        const dump_count = countDumps(g.all);

        var score_buf: [8]u8 = undefined;
        const score_str = try color.formatScore(g.cvss.score, &score_buf);
        try out.print("\n{s}[{d}] {s}{s}  {s}{s}{s}", .{
            c.cyan,                          gi,        g.display_label, c.reset,
            c.forSeverity(g.cvss.severity), score_str, c.reset,
        });
        if (idxs.len == 0 and dump_count == 0) {
            try out.writeAll("  (no hits)\n");
        } else if (dump_count > 0) {
            try out.print("  ({d} shown, {s}{d} filtered as CVE-list dump(s){s})\n", .{ idxs.len, c.yellow, dump_count, c.reset });
        } else {
            try out.print("  ({d} shown)\n", .{idxs.len});
        }

        for (idxs, 1..) |idx, hi| try renderHit(out, c, g.all[idx], gi, hi);
    }
}

fn printHelp(out: *std.Io.Writer) !void {
    try out.writeAll(
        \\commands:
        \\  list                    reprint the current listing
        \\  expand <target...>      show the full readme for one or more hits (e.g. `expand 1` or `expand 1.2`)
        \\  select <target...>      mark hits for download (`select 1` selects every hit under CVE 1)
        \\  unselect <target...>    unmark hits
        \\  dir [path]              show or set the download directory
        \\  download                clone every selected hit into <dir>/<group>/...
        \\  show-all                also show hits filtered out as CVE-list dumps
        \\  hide-dumps              hide them again
        \\  help                    this message
        \\  quit                    exit
        \\
        \\targets: N (a whole group) or N.M (one hit within it), space-separated, mixable
        \\e.g. `select 1 2.3` selects all of group 1's hits plus just hit 3 of group 2.
        \\
    );
}

const Target = struct { group: usize, hit: ?usize };

fn parseTarget(tok: []const u8) ?Target {
    if (std.mem.indexOfScalar(u8, tok, '.')) |dot| {
        const g = std.fmt.parseInt(usize, tok[0..dot], 10) catch return null;
        const h = std.fmt.parseInt(usize, tok[dot + 1 ..], 10) catch return null;
        if (g == 0 or h == 0) return null;
        return .{ .group = g, .hit = h };
    }
    const g = std.fmt.parseInt(usize, tok, 10) catch return null;
    if (g == 0) return null;
    return .{ .group = g, .hit = null };
}

fn applyToTargets(out: *std.Io.Writer, groups: []Group, visible: []const []usize, it: anytype, select: bool) !void {
    var touched: usize = 0;
    while (it.next()) |tok| {
        const target = parseTarget(tok) orelse {
            try out.print("bad target: {s} (expected N or N.M)\n", .{tok});
            continue;
        };
        if (target.group == 0 or target.group > groups.len) {
            try out.print("no such group: {d}\n", .{target.group});
            continue;
        }
        const gi = target.group - 1;
        const idxs = visible[gi];

        if (target.hit) |h| {
            if (h == 0 or h > idxs.len) {
                try out.print("no such hit: {d}.{d}\n", .{ target.group, h });
                continue;
            }
            groups[gi].all[idxs[h - 1]].selected = select;
            touched += 1;
        } else {
            for (idxs) |idx| groups[gi].all[idx].selected = select;
            touched += idxs.len;
        }
    }
    try out.print("{s} {d} hit(s).\n", .{ if (select) "selected" else "unselected", touched });
}

fn printExpanded(out: *std.Io.Writer, c: color.Colors, e: HitEntry, group_num: usize, hit_num: usize) !void {
    try out.print("\n{s}--- {d}.{d}  {s} ---{s}\n{s}\n", .{
        c.dim,
        group_num,
        hit_num,
        e.hit.full_name,
        c.reset,
        if (e.hit.readme_full.len > 0) e.hit.readme_full else "(no readme found)",
    });
}

fn expandTargets(out: *std.Io.Writer, c: color.Colors, groups: []const Group, visible: []const []usize, it: anytype) !void {
    var any = false;
    while (it.next()) |tok| {
        const target = parseTarget(tok) orelse {
            try out.print("bad target: {s} (expected N or N.M)\n", .{tok});
            continue;
        };
        if (target.group == 0 or target.group > groups.len) {
            try out.print("no such group: {d}\n", .{target.group});
            continue;
        }
        const gi = target.group - 1;
        const idxs = visible[gi];

        if (target.hit) |h| {
            if (h == 0 or h > idxs.len) {
                try out.print("no such hit: {d}.{d}\n", .{ target.group, h });
                continue;
            }
            try printExpanded(out, c, groups[gi].all[idxs[h - 1]], target.group, h);
            any = true;
        } else {
            for (idxs, 1..) |idx, hi| {
                try printExpanded(out, c, groups[gi].all[idx], target.group, hi);
                any = true;
            }
        }
    }
    if (!any) try out.writeAll("nothing expanded.\n");
}

fn doDownload(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, groups: []const Group, dir: []const u8, opts: Options) !void {
    var count: usize = 0;
    for (groups) |g| {
        for (g.all) |e| {
            if (!e.selected) continue;
            count += 1;
            const mode = switch (e.hit.host) {
                .github => opts.gh_mode,
                .gitlab => opts.gl_mode,
                .codeberg => opts.cb_mode,
                .exploitdb => .none, // unused: exploitdb.download needs no auth
            };
            const result = try download.downloadOne(allocator, io, dir, g.dir_name, e.hit, mode);
            if (result.ok) {
                try out.print("  ok    {s} -> {s}\n", .{ e.hit.full_name, result.dest });
            } else {
                try out.print("  FAIL  {s}: {s}\n", .{ e.hit.full_name, result.err_name });
            }
        }
    }
    if (count == 0) {
        try out.writeAll("nothing selected -- use `select <target>` first.\n");
    } else {
        try out.print("downloaded {d} repo(s) into {s}\n", .{ count, dir });
    }
}

fn readYesNo(in: *std.Io.Reader) bool {
    const line_opt = in.takeDelimiter('\n') catch return false;
    const line = line_opt orelse return false;
    const t = std.mem.trim(u8, line, " \t\r");
    return t.len > 0 and (t[0] == 'y' or t[0] == 'Y');
}

/// Same shape as main.zig's per-CVE host tasks: one host's full
/// "search, then fetch every readme" pipeline, run via `std.Io.async` so
/// the three hosts overlap instead of running one after another, while
/// still issuing at most one request at a time to any single host. Each
/// task owns a page_allocator-backed arena that's intentionally never
/// deinit'd -- see the identical comment on main.zig's fetchGithubHits.
fn fetchGithubSearchHits(io: std.Io, mode: auth.AuthMode, query: []const u8, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try github.search(a, io, mode, query, per_page);
    for (result.hits) |*h| github.fetchReadme(a, io, mode, h);
    return result;
}

fn fetchGitlabSearchHits(io: std.Io, mode: auth.AuthMode, query: []const u8, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try gitlab.search(a, io, mode, query, per_page);
    for (result.hits) |*h| gitlab.fetchReadme(a, io, mode, h);
    return result;
}

fn fetchCodebergSearchHits(io: std.Io, mode: auth.AuthMode, query: []const u8, per_page: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try codeberg.search(a, io, mode, query, per_page);
    for (result.hits) |*h| codeberg.fetchReadme(a, io, mode, h);
    return result;
}

fn fetchExploitdbSearchHits(io: std.Io, db: ?*const exploitdb.Database, query: []const u8, max_results: usize, enabled: bool) !forge.SearchResult {
    if (!enabled) return .{ .hits = &.{} };
    const database = db orelse return .{ .hits = &.{} };
    var task_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    const a = task_arena.allocator();
    const result = try exploitdb.search(a, database, query, max_results);
    for (result.hits) |*h| exploitdb.fetchReadme(a, io, h);
    return result;
}

/// Zero-hits fallback: search all 4 sources for "<query> CVE" as a plain
/// keyword (not tied to any specific CVE ID) and wrap the merged results as
/// one more group, appended after the real per-CVE ones.
fn runGenericSearch(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, c: color.Colors, query: []const u8, opts: Options) !Group {
    const full_query = try std.fmt.allocPrint(allocator, "{s} CVE", .{query});

    try out.print("searching github + gitlab + codeberg + exploitdb for \"{s}\"...\n", .{full_query});
    try out.flush();

    var gh_future = std.Io.async(io, fetchGithubSearchHits, .{ io, opts.gh_mode, full_query, opts.fallback_per_page, opts.sources.contains(.github) });
    var gl_future = std.Io.async(io, fetchGitlabSearchHits, .{ io, opts.gl_mode, full_query, opts.fallback_per_page, opts.sources.contains(.gitlab) });
    var cb_future = std.Io.async(io, fetchCodebergSearchHits, .{ io, opts.cb_mode, full_query, opts.fallback_per_page, opts.sources.contains(.codeberg) });
    var edb_future = std.Io.async(io, fetchExploitdbSearchHits, .{ io, opts.edb_db, full_query, opts.fallback_per_page, opts.sources.contains(.exploitdb) });

    const gh_result = try gh_future.await(io);
    const gl_result = try gl_future.await(io);
    const cb_result = try cb_future.await(io);
    const edb_result = try edb_future.await(io);

    var rate_limited: std.EnumSet(forge.Host) = .initEmpty();
    if (gh_result.rate_limited) rate_limited.insert(.github);
    if (gl_result.rate_limited) rate_limited.insert(.gitlab);
    if (cb_result.rate_limited) rate_limited.insert(.codeberg);
    if (edb_result.rate_limited) rate_limited.insert(.exploitdb);
    if (rate_limited.count() > 0) {
        try out.print("{s}warning:{s} rate-limited during the fallback search -- its results may be incomplete.\n", .{ c.yellow, c.reset });
    }

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

    try filter.annotate(allocator, merged, opts.threshold);

    const dir_name = try forge.sanitizeDirName(allocator, full_query);
    const display_label = try std.fmt.allocPrint(allocator, "\"{s}\" (generic fallback search)", .{full_query});

    return toGroup(allocator, .{ .display_label = display_label, .dir_name = dir_name, .hits = merged, .rate_limited = rate_limited });
}

/// Runs the interactive REPL until `quit`/`exit` or stdin EOF. `raw` is one
/// entry per CVE with `.hits` = every annotated candidate for that CVE
/// (all hosts merged, dump-flagged ones included -- filter.annotate() must
/// already have run; this function does the show/hide + numbering itself so
/// the show-all toggle can work live without re-fetching anything).
///
/// `out`/`in` are owned by the caller (main.zig constructs them once for the
/// whole program) rather than by this function -- if the setup wizard already
/// ran earlier in the same process, it read from the same stdin stream, and
/// two independently-buffered `Io.File.Reader`s over one fd can lose
/// already-buffered-but-unconsumed input between them.
pub fn run(allocator: std.mem.Allocator, io: std.Io, out: *std.Io.Writer, in: *std.Io.Reader, raw: []forge.CveGroup, opts: Options) !void {
    var groups_list = try buildGroups(allocator, raw);
    var show_all = opts.show_all;
    var download_dir: []const u8 = opts.default_download_dir;
    const c = color.detectColors(io);

    if (opts.fallback_query) |query| {
        if (totalHits(groups_list.items) == 0) {
            try out.print(
                "\nNo repo hits found for any CVE. Search github + gitlab + codeberg for \"{s} CVE\" instead? [y/N] ",
                .{query},
            );
            try out.flush();
            if (readYesNo(in)) {
                const fallback_group = try runGenericSearch(allocator, io, out, c, query, opts);
                // Every per-CVE group is empty (that's the trigger condition
                // for even offering this) -- replace them rather than
                // appending, so the listing doesn't lead with a wall of
                // "(no hits)" groups nobody asked to see.
                groups_list.clearRetainingCapacity();
                try groups_list.append(allocator, fallback_group);
            } else {
                try out.writeAll("ok, skipping.\n");
            }
        }
    }

    // Nothing to select, expand, or download -- whether that's because no
    // CVE turned up a single repo hit, or the fallback search (declined,
    // or accepted but also empty) didn't change that. Don't drop into the
    // full REPL with an all-empty listing and a command menu for nothing.
    if (totalHits(groups_list.items) == 0) {
        try out.writeAll("\nno PoCs found -- nothing to select.\n");
        try out.flush();
        return;
    }

    const groups = groups_list.items;
    var visible = try buildVisible(allocator, groups, show_all, opts.max_hits);
    try renderAll(out, c, groups, visible);
    try printHelp(out);
    try out.flush();

    while (true) {
        try out.writeAll("\n> ");
        try out.flush();

        const line_opt = in.takeDelimiter('\n') catch |err| {
            try out.print("input error: {s}\n", .{@errorName(err)});
            try out.flush();
            continue;
        };
        const raw_line = line_opt orelse break; // stdin closed
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        var it = std.mem.tokenizeAny(u8, line, " \t");
        const cmd = it.next() orelse continue;

        if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "exit")) {
            break;
        } else if (std.mem.eql(u8, cmd, "help")) {
            try printHelp(out);
        } else if (std.mem.eql(u8, cmd, "list")) {
            try renderAll(out, c, groups, visible);
        } else if (std.mem.eql(u8, cmd, "show-all")) {
            show_all = true;
            visible = try buildVisible(allocator, groups, show_all, opts.max_hits);
            try out.writeAll("showing all hits, including likely CVE-list dumps.\n");
            try renderAll(out, c, groups, visible);
        } else if (std.mem.eql(u8, cmd, "hide-dumps")) {
            show_all = false;
            visible = try buildVisible(allocator, groups, show_all, opts.max_hits);
            try out.writeAll("hiding likely CVE-list dumps again.\n");
            try renderAll(out, c, groups, visible);
        } else if (std.mem.eql(u8, cmd, "dir")) {
            const rest = std.mem.trim(u8, it.rest(), " \t");
            if (rest.len == 0) {
                try out.print("current download directory: {s}\n", .{download_dir});
            } else {
                download_dir = try allocator.dupe(u8, rest);
                try out.print("download directory set to: {s}\n", .{download_dir});
            }
        } else if (std.mem.eql(u8, cmd, "select")) {
            try applyToTargets(out, groups, visible, &it, true);
        } else if (std.mem.eql(u8, cmd, "unselect")) {
            try applyToTargets(out, groups, visible, &it, false);
        } else if (std.mem.eql(u8, cmd, "expand")) {
            try expandTargets(out, c, groups, visible, &it);
        } else if (std.mem.eql(u8, cmd, "download")) {
            try doDownload(allocator, io, out, groups, download_dir, opts);
        } else {
            try out.print("unknown command: {s} (try `help`)\n", .{cmd});
        }
        try out.flush();
    }
    try out.flush();
}

test "parseTarget accepts bare group and group.hit forms, rejects garbage" {
    try std.testing.expectEqual(Target{ .group = 1, .hit = null }, parseTarget("1").?);
    try std.testing.expectEqual(Target{ .group = 2, .hit = 3 }, parseTarget("2.3").?);
    try std.testing.expectEqual(@as(?Target, null), parseTarget("0"));
    try std.testing.expectEqual(@as(?Target, null), parseTarget("1.0"));
    try std.testing.expectEqual(@as(?Target, null), parseTarget("abc"));
}
