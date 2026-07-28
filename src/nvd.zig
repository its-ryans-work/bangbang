const std = @import("std");
const cve = @import("cve.zig");
const forge = @import("forge.zig");

/// NVD's documented max page size, regardless of API key.
const max_results_per_page: usize = 2000;

/// Hard ceiling on total CVEs pulled for one keyword, independent of NVD's
/// own totalResults. Not a "top N" cutoff in the old sense (there's no
/// relevance ordering being truncated) -- just a backstop so a wildly broad
/// keyword can't loop against NVD indefinitely or produce an unusable REPL.
pub const safety_cap: usize = 5000;

/// One CVE plus its headline CVSS score/severity, as resolved by a single
/// NVD lookup (keyword search or by-ID).
pub const CveMatch = struct {
    id: cve.CveId,
    cvss: cve.Cvss = .{},
};

/// Shared "GET this URL, capture the body, error on non-2xx" plumbing behind
/// both fetchPage (keyword search) and fetchById (single-CVE lookup) -- the
/// only thing that differs between them is how the URL is built.
fn httpGetBody(gpa: std.mem.Allocator, io: std.Io, url: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();

    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body.writer,
    });
    if (result.status != .ok) return error.NvdRequestFailed;

    var al = body.toArrayList();
    return try al.toOwnedSlice(gpa);
}

/// Raw HTTPS GET against one page of the NVD keyword-search API. Kept
/// separate from JSON parsing so this one function is the whole surface to
/// swap for a `curl` subprocess (matching the std.process.run pattern used
/// elsewhere) if std.http.Client ever proves unreliable in practice.
pub fn fetchPage(gpa: std.mem.Allocator, io: std.Io, keyword: []const u8, api_key: ?[]const u8, start_index: usize) ![]u8 {
    var url_buf: std.Io.Writer.Allocating = .init(gpa);
    defer url_buf.deinit();
    try url_buf.writer.writeAll("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=");
    try (std.Uri.Component{ .raw = keyword }).formatQuery(&url_buf.writer);
    try url_buf.writer.print("&resultsPerPage={d}&startIndex={d}", .{ max_results_per_page, start_index });
    if (api_key) |k| {
        try url_buf.writer.writeAll("&apiKey=");
        try (std.Uri.Component{ .raw = k }).formatQuery(&url_buf.writer);
    }
    return httpGetBody(gpa, io, url_buf.written());
}

const Page = struct {
    matches: []CveMatch,
    total_results: usize,
};

fn firstMetric(metrics: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const arr_val = metrics.get(key) orelse return null;
    if (arr_val != .array or arr_val.array.items.len == 0) return null;
    const first = arr_val.array.items[0];
    if (first != .object) return null;
    return first.object;
}

/// v4.0/v3.1/v3.0 all nest baseSeverity inside cvssData.
fn cvssFromV3(metric: std.json.ObjectMap) cve.Cvss {
    const data_val = metric.get("cvssData") orelse return .{};
    if (data_val != .object) return .{};
    const data = data_val.object;
    const sev_str = forge.jsonStr(data, "baseSeverity") orelse "";
    return .{ .score = forge.jsonFloat(data, "baseScore"), .severity = cve.Severity.fromNvdString(sev_str) };
}

/// CVSS v2 has no baseSeverity concept in its own spec -- NVD attaches one
/// as a sibling field on the metric object itself instead of inside
/// cvssData (confirmed live against a v2-only historical CVE).
fn cvssFromV2(metric: std.json.ObjectMap) cve.Cvss {
    const data_val = metric.get("cvssData") orelse return .{};
    if (data_val != .object) return .{};
    const data = data_val.object;
    const sev_str = forge.jsonStr(metric, "baseSeverity") orelse "";
    return .{ .score = forge.jsonFloat(data, "baseScore"), .severity = cve.Severity.fromNvdString(sev_str) };
}

/// Picks the newest CVSS standard NVD has published for this CVE: v4.0 >
/// v3.1 > v3.0 > v2. Confirmed live that a single CVE can carry several
/// versions at once (e.g. both v4.0 and v3.1, with different scores) --
/// newest wins rather than averaging or preferring "Primary" source.
fn extractCvss(cve_obj: std.json.ObjectMap) cve.Cvss {
    const metrics_val = cve_obj.get("metrics") orelse return .{};
    if (metrics_val != .object) return .{};
    const metrics = metrics_val.object;

    if (firstMetric(metrics, "cvssMetricV40")) |m| return cvssFromV3(m);
    if (firstMetric(metrics, "cvssMetricV31")) |m| return cvssFromV3(m);
    if (firstMetric(metrics, "cvssMetricV30")) |m| return cvssFromV3(m);
    if (firstMetric(metrics, "cvssMetricV2")) |m| return cvssFromV2(m);
    return .{};
}

/// Parses one NVD 2.0 response page (keyword-search or by-ID -- both share
/// the same `.vulnerabilities[].cve` shape): every CVE id plus its CVSS
/// data, and the top-level `totalResults` (needed for pagination). Skips
/// (doesn't error on) any entry whose id isn't in the expected grammar
/// rather than failing the whole page.
fn parsePage(allocator: std.mem.Allocator, body: []const u8) !Page {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.UnexpectedNvdResponse;
    const obj = parsed.value.object;

    const vulns_val = obj.get("vulnerabilities") orelse return error.UnexpectedNvdResponse;
    if (vulns_val != .array) return error.UnexpectedNvdResponse;

    var matches: std.ArrayList(CveMatch) = .empty;
    defer matches.deinit(allocator);

    for (vulns_val.array.items) |v| {
        if (v != .object) continue;
        const cve_obj_val = v.object.get("cve") orelse continue;
        if (cve_obj_val != .object) continue;
        const cve_obj = cve_obj_val.object;
        const id_val = cve_obj.get("id") orelse continue;
        if (id_val != .string) continue;
        const id = cve.parseExact(id_val.string) orelse continue;
        try matches.append(allocator, .{ .id = id, .cvss = extractCvss(cve_obj) });
    }

    const total: usize = blk: {
        const t = obj.get("totalResults") orelse break :blk matches.items.len;
        if (t != .integer or t.integer < 0) break :blk matches.items.len;
        break :blk @intCast(t.integer);
    };

    return .{ .matches = try matches.toOwnedSlice(allocator), .total_results = total };
}

fn matchLessThanDesc(_: void, a: CveMatch, b: CveMatch) bool {
    return a.id.order(b.id) == .gt;
}

/// Returns a newly allocated, deduped (by id) copy of `items` sorted
/// newest-first. Mirrors cve.dedupSortedDesc but keyed off `.id` since each
/// item also carries CVSS data that needs to travel with it -- can't reuse
/// that helper directly without losing the severity/score pairing.
fn dedupSortedDescMatches(allocator: std.mem.Allocator, items: []const CveMatch) ![]CveMatch {
    const buf = try allocator.dupe(CveMatch, items);
    std.sort.pdq(CveMatch, buf, {}, matchLessThanDesc);

    if (buf.len == 0) return buf;
    var w: usize = 1;
    for (buf[1..]) |item| {
        if (!item.id.eql(buf[w - 1].id)) {
            buf[w] = item;
            w += 1;
        }
    }
    if (w == buf.len) return buf;
    return try allocator.realloc(buf, w);
}

/// Parses a single NVD response page in isolation (used directly by tests;
/// `search` below is the real paginating entry point).
pub fn parseMatches(allocator: std.mem.Allocator, body: []const u8) ![]CveMatch {
    const page = try parsePage(allocator, body);
    defer allocator.free(page.matches);
    return dedupSortedDescMatches(allocator, page.matches);
}

/// Keyword -> deduped, newest-first CVE matches (id + CVSS), covering
/// *every* match NVD has (not just the first page) up to `safety_cap`. Most
/// keywords fit in a single 2000-result page; pagination only kicks in for
/// genuinely broad terms.
pub fn search(gpa: std.mem.Allocator, io: std.Io, keyword: []const u8, api_key: ?[]const u8) ![]CveMatch {
    var all: std.ArrayList(CveMatch) = .empty;
    defer all.deinit(gpa);

    var start_index: usize = 0;
    var total_results: usize = max_results_per_page; // unknown until the first page comes back

    while (start_index < total_results and start_index < safety_cap) {
        const raw = try fetchPage(gpa, io, keyword, api_key, start_index);
        defer gpa.free(raw);

        const page = try parsePage(gpa, raw);
        defer gpa.free(page.matches);

        try all.appendSlice(gpa, page.matches);
        total_results = @min(page.total_results, safety_cap);
        start_index += max_results_per_page;
    }

    return dedupSortedDescMatches(gpa, all.items);
}

/// Looks up CVSS data for one literal CVE ID (the non-keyword-search entry
/// point, e.g. `bangbang CVE-2023-22515`). NVD returns HTTP 200 with an
/// empty `vulnerabilities` array for a well-formed but unknown/nonexistent
/// ID (confirmed live -- not a 404), so "not found" surfaces as `null`
/// rather than an error.
pub fn fetchById(gpa: std.mem.Allocator, io: std.Io, id: cve.CveId, api_key: ?[]const u8) !?CveMatch {
    var id_buf: [16]u8 = undefined;
    const id_str = try id.toSlice(&id_buf);

    var url_buf: std.Io.Writer.Allocating = .init(gpa);
    defer url_buf.deinit();
    try url_buf.writer.writeAll("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=");
    try (std.Uri.Component{ .raw = id_str }).formatQuery(&url_buf.writer);
    if (api_key) |k| {
        try url_buf.writer.writeAll("&apiKey=");
        try (std.Uri.Component{ .raw = k }).formatQuery(&url_buf.writer);
    }

    const raw = try httpGetBody(gpa, io, url_buf.written());
    defer gpa.free(raw);

    const page = try parsePage(gpa, raw);
    defer gpa.free(page.matches);
    if (page.matches.len == 0) return null;
    return page.matches[0];
}

test "parseMatches pulls ids out of an NVD-shaped response and ignores malformed entries" {
    const allocator = std.testing.allocator;
    const sample =
        \\{
        \\  "totalResults": 2,
        \\  "vulnerabilities": [
        \\    {"cve": {"id": "CVE-2023-22515", "descriptions": []}},
        \\    {"cve": {"id": "CVE-2021-44228"}},
        \\    {"cve": {"id": "not-a-cve-id"}},
        \\    {"cve": {}}
        \\  ]
        \\}
    ;
    const matches = try parseMatches(allocator, sample);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 2), matches.len);
    try std.testing.expectEqual(cve.CveId{ .year = 2023, .sequence = 22515 }, matches[0].id);
    try std.testing.expectEqual(cve.CveId{ .year = 2021, .sequence = 44228 }, matches[1].id);
}

test "parsePage reports totalResults so the caller knows whether to fetch another page" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"totalResults": 4321, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}
    ;
    const page = try parsePage(allocator, sample);
    defer allocator.free(page.matches);

    try std.testing.expectEqual(@as(usize, 4321), page.total_results);
    try std.testing.expectEqual(@as(usize, 1), page.matches.len);
}

test "extractCvss prefers v3.1 baseScore/baseSeverity nested inside cvssData" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2023-22515", "metrics": {
        \\  "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
        \\}}}]}
    ;
    const matches = try parseMatches(allocator, sample);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(?f64, 9.8), matches[0].cvss.score);
    try std.testing.expectEqual(cve.Severity.critical, matches[0].cvss.severity);
}

test "extractCvss prefers v4.0 over v3.1 when both are present" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-50189", "metrics": {
        \\  "cvssMetricV40": [{"cvssData": {"baseScore": 8.9, "baseSeverity": "HIGH"}}],
        \\  "cvssMetricV31": [{"cvssData": {"baseScore": 7.2, "baseSeverity": "HIGH"}}]
        \\}}}]}
    ;
    const matches = try parseMatches(allocator, sample);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(?f64, 8.9), matches[0].cvss.score);
}

test "extractCvss falls back to v2's sibling baseSeverity field when only v2 data exists" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2002-0001", "metrics": {
        \\  "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]
        \\}}}]}
    ;
    const matches = try parseMatches(allocator, sample);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(?f64, 7.5), matches[0].cvss.score);
    try std.testing.expectEqual(cve.Severity.high, matches[0].cvss.severity);
}

test "extractCvss defaults to null score / none severity when a CVE has no metrics at all" {
    const allocator = std.testing.allocator;
    const sample =
        \\{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-99999"}}]}
    ;
    const matches = try parseMatches(allocator, sample);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(?f64, null), matches[0].cvss.score);
    try std.testing.expectEqual(cve.Severity.none, matches[0].cvss.severity);
}
