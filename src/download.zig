const std = @import("std");
const forge = @import("forge.zig");
const auth = @import("auth.zig");
const github = @import("github.zig");
const gitlab = @import("gitlab.zig");
const codeberg = @import("codeberg.zig");
const exploitdb = @import("exploitdb.zig");

pub const Result = struct {
    hit: forge.RepoHit,
    dest: []const u8,
    ok: bool,
    err_name: []const u8 = "",
};

/// Clones `hit` into `<base_dir>/<dir_name>/<host>-<owner>__<name>/`
/// (`dir_name` is normally a CVE ID, or a sanitized fallback-search label for
/// the zero-hits generic search -- see `forge.CveGroup.dir_name`), creating
/// the parent directory first (the final repo directory is left for
/// git/gh/glab clone to create -- it must not already exist).
///
/// Never propagates a clone/mkdir failure as a Zig error -- those come back
/// as `ok = false` with `err_name` set, so a caller looping over several
/// selected hits doesn't need per-iteration try/catch to keep going after
/// one failure. Only allocation failure propagates (`error.OutOfMemory`).
pub fn downloadOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    base_dir: []const u8,
    dir_name: []const u8,
    hit: forge.RepoHit,
    mode: auth.AuthMode,
    environ: *const std.process.Environ.Map,
) !Result {
    const parent_dir = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_dir, dir_name });
    std.Io.Dir.cwd().createDirPath(io, parent_dir) catch |err| {
        return .{ .hit = hit, .dest = parent_dir, .ok = false, .err_name = @errorName(err) };
    };

    // owner/name are remote-controlled (a forge API's response, or exploit-db's
    // CSV). Sanitizing here rather than at each source means a new host can't
    // reintroduce a traversal by forgetting to do it: whatever they contain,
    // each can only ever contribute one harmless path component.
    const safe_owner = try forge.sanitizePathComponent(allocator, hit.owner);
    const safe_name = try forge.sanitizePathComponent(allocator, hit.name);
    const dest = try std.fmt.allocPrint(allocator, "{s}/{s}-{s}__{s}", .{
        parent_dir, hit.host.label(), safe_owner, safe_name,
    });

    const clone_err: ?anyerror = switch (hit.host) {
        .github => if (github.clone(allocator, io, mode, hit, dest, environ)) |_| null else |err| err,
        .gitlab => if (gitlab.clone(allocator, io, mode, hit, dest, environ)) |_| null else |err| err,
        .codeberg => if (codeberg.clone(allocator, io, mode, hit, dest, environ)) |_| null else |err| err,
        // No repo to clone -- writes the single exploit file into `dest`
        // instead. No auth involved, so `mode` is unused here.
        .exploitdb => if (exploitdb.download(allocator, io, hit, dest)) |_| null else |err| err,
    };

    if (clone_err) |err| {
        return .{ .hit = hit, .dest = dest, .ok = false, .err_name = @errorName(err) };
    }
    return .{ .hit = hit, .dest = dest, .ok = true };
}

test "downloadOne reports failure without erroring when the destination is unusable" {
    // A destination path through a file (not a directory) can't be mkdir -p'd
    // -- this should come back as a normal ok=false Result, not a thrown error.
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "blocker", .data = "not a directory" });
    const scratch = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/blocker", .{tmp.sub_path});
    defer allocator.free(scratch);

    const hit = forge.RepoHit{
        .host = .github,
        .owner = "owner",
        .name = "name",
        .full_name = "owner/name",
        .stars = 0,
        .description = "",
        .readme_excerpt = "",
        .readme_full = "",
    };
    const result = try downloadOne(allocator, io, scratch, "CVE-2023-0001", hit, .none);
    defer allocator.free(result.dest);

    try std.testing.expect(!result.ok);
    try std.testing.expect(result.err_name.len > 0);
}
