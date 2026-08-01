/// Cfg is zmx's configuration container.
///
/// The purpose of this container is to hold anything that can be modified by the user.
pub const Cfg = @This();

const std = @import("std");
const lib_posix = @import("posix.zig");
const c = @cImport({
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub const default_dir_mode: std.posix.mode_t = 0o700;
pub const default_log_mode: std.posix.mode_t = 0o600;

pub const Owner = struct {
    uid: std.posix.uid_t,
    gid: std.posix.gid_t,
};

socket_dir: []const u8,
log_dir: []const u8,
dir_mode: std.posix.mode_t = default_dir_mode,
log_mode: std.posix.mode_t = default_log_mode,
socket_mode: std.posix.mode_t = socketMode(default_dir_mode),
socket_owner: Owner = .{ .uid = 0, .gid = 0 },
log_owner: Owner = .{ .uid = 0, .gid = 0 },
max_scrollback: usize = 10_000_000,

pub fn init(alloc: std.mem.Allocator, io: std.Io) !Cfg {
    const dir_mode = parseEnvMode(io, "ZMX_DIR_MODE", default_dir_mode) catch
        return error.InvalidModeConfiguration;
    const log_mode = parseEnvMode(io, "ZMX_LOG_MODE", default_log_mode) catch
        return error.InvalidModeConfiguration;

    const socket_dir = try socketDir(alloc);
    errdefer alloc.free(socket_dir);
    const log_dir = try logDir(alloc);
    errdefer alloc.free(log_dir);

    var cfg = Cfg{
        .socket_dir = socket_dir,
        .log_dir = log_dir,
        .dir_mode = dir_mode,
        .log_mode = log_mode,
        .socket_mode = socketMode(dir_mode),
    };

    try cfg.mkdir(io);

    return cfg;
}

fn socketDir(alloc: std.mem.Allocator) ![]const u8 {
    const tmpdir = std.mem.trimEnd(u8, lib_posix.getenv("TMPDIR") orelse "/tmp", "/");
    const uid = lib_posix.getuid();

    const socket_dir: []const u8 = if (lib_posix.getenv("ZMX_DIR")) |zmxdir|
        try alloc.dupe(u8, zmxdir)
    else if (lib_posix.getenv("XDG_RUNTIME_DIR")) |xdg_runtime|
        try std.fmt.allocPrint(alloc, "{s}/zmx", .{xdg_runtime})
    else
        try std.fmt.allocPrint(alloc, "{s}/zmx-{d}", .{ tmpdir, uid });

    return socket_dir;
}

fn logDir(alloc: std.mem.Allocator) ![]const u8 {
    const log_dir = if (lib_posix.getenv("ZMX_DIR")) |zmxdir|
        try std.fmt.allocPrint(alloc, "{s}/logs", .{zmxdir})
    else if (lib_posix.getenv("XDG_STATE_HOME")) |xdg_state_home|
        try std.fmt.allocPrint(alloc, "{s}/zmx/logs", .{xdg_state_home})
    else if (lib_posix.getenv("HOME")) |home_dir|
        try std.fmt.allocPrint(alloc, "{s}/.local/state/zmx/logs", .{home_dir})
    else fallback: {
        // Keep logs in their own namespace even in the last-resort runtime
        // directory so session sockets can never collide with *.log files.
        const tmpdir = std.mem.trimEnd(u8, lib_posix.getenv("TMPDIR") orelse "/tmp", "/");
        const uid = lib_posix.getuid();
        break :fallback try std.fmt.allocPrint(alloc, "{s}/zmx-{d}/logs", .{ tmpdir, uid });
    };

    return log_dir;
}

pub fn deinit(self: *Cfg, alloc: std.mem.Allocator) void {
    if (self.socket_dir.len > 0) alloc.free(self.socket_dir);
    if (self.log_dir.len > 0) alloc.free(self.log_dir);
}

pub fn mkdir(self: *Cfg, io: std.Io) !void {
    self.socket_owner = try mkdirAll(io, self.socket_dir, self.dir_mode, null);
    const log_anchor: ?Owner = if (isDirectChild(self.socket_dir, self.log_dir))
        self.socket_owner
    else
        null;
    self.log_owner = try mkdirAll(io, self.log_dir, self.dir_mode, log_anchor);
}

fn isDirectChild(parent_path: []const u8, child_path: []const u8) bool {
    const parent = if (parent_path.len > 1) std.mem.trimEnd(u8, parent_path, "/") else parent_path;
    const child = if (child_path.len > 1) std.mem.trimEnd(u8, child_path, "/") else child_path;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    const relative = std.mem.trimStart(u8, child[parent.len..], "/");
    return std.mem.eql(u8, relative, "logs");
}

fn mkdirAll(
    io: std.Io,
    sub_dir_path: []const u8,
    expected_mode: std.posix.mode_t,
    required_owner: ?Owner,
) !Owner {
    const target_path = if (sub_dir_path.len > 1)
        std.mem.trimEnd(u8, sub_dir_path, "/")
    else
        sub_dir_path;

    // A nested namespace anchored to a service-owned runtime directory may
    // be created only by that owner and effective group. Otherwise a trusted
    // group client could establish a replacement directory under its own UID.
    if (required_owner) |owner| {
        if (c.geteuid() != owner.uid or
            (expected_mode & 0o070 != 0 and c.getegid() != owner.gid))
        {
            var existing = std.Io.Dir.openDirAbsolute(io, target_path, .{
                .access_sub_paths = true,
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                reportInsecureDirectory(target_path, expected_mode, err);
                return error.InsecureDirectory;
            };
            existing.close(io);
        }
    }

    var it = std.fs.path.componentIterator(target_path);
    var component = it.last() orelse return error.BadPathName;
    while (true) {
        const is_target = component.path.len == target_path.len;
        // Missing system/user parents are created conservatively. A custom
        // zmx mode applies only to the configured runtime/log directory, not
        // to unrelated ancestors such as $HOME/.local or /srv/shared.
        const component_mode = if (is_target) expected_mode else default_dir_mode;
        const permissions: std.Io.Dir.Permissions = .fromMode(@intCast(component_mode));
        var existing = false;
        std.Io.Dir.createDirAbsolute(io, component.path, permissions) catch |err| switch (err) {
            error.PathAlreadyExists => {
                existing = true;
                var dir = std.Io.Dir.openDirAbsolute(io, component.path, .{
                    .access_sub_paths = true,
                    .iterate = true,
                    .follow_symlinks = false,
                }) catch |open_err| {
                    reportInsecureDirectory(component.path, expected_mode, open_err);
                    return error.InsecureDirectory;
                };
                defer dir.close(io);
                const stat = statDirectory(dir) catch |stat_err| {
                    reportInsecureDirectory(component.path, expected_mode, stat_err);
                    return error.InsecureDirectory;
                };

                if (is_target) {
                    validateDirectoryAccess(stat, expected_mode) catch |validate_err| {
                        reportInsecureDirectory(component.path, expected_mode, validate_err);
                        return error.InsecureDirectory;
                    };
                    if (required_owner) |owner| {
                        validateAnchoredDirectoryMetadata(stat, expected_mode, owner) catch |validate_err| {
                            reportInsecureDirectory(component.path, expected_mode, validate_err);
                            return error.InsecureDirectory;
                        };
                    }
                } else {
                    // System/user-owned parents such as /tmp and $HOME are not
                    // zmx directories, but must still be real directories.
                    validateDirectoryType(stat) catch |validate_err| {
                        reportInsecureDirectory(component.path, expected_mode, validate_err);
                        return error.InsecureDirectory;
                    };
                }
            },
            error.FileNotFound => |e| {
                component = it.previous() orelse return e;
                continue;
            },
            else => |e| return e,
        };

        if (!existing) {
            // The directory was newly created above. mkdir(2) honors umask, so
            // explicitly set the mode and validate the opened object rather
            // than the path.
            var dir = std.Io.Dir.openDirAbsolute(io, component.path, .{
                .access_sub_paths = true,
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                reportInsecureDirectory(component.path, expected_mode, err);
                return error.InsecureDirectory;
            };
            defer dir.close(io);
            dir.setPermissions(io, permissions) catch |err| {
                reportInsecureDirectory(component.path, expected_mode, err);
                return error.InsecureDirectory;
            };
            const stat = statDirectory(dir) catch |err| {
                reportInsecureDirectory(component.path, expected_mode, err);
                return error.InsecureDirectory;
            };
            validateDirectoryMetadata(stat, component_mode, c.geteuid()) catch |err| {
                reportInsecureDirectory(component.path, component_mode, err);
                return error.InsecureDirectory;
            };
            if (is_target) {
                if (required_owner) |owner| {
                    validateAnchoredDirectoryMetadata(stat, expected_mode, owner) catch |err| {
                        reportInsecureDirectory(component.path, expected_mode, err);
                        return error.InsecureDirectory;
                    };
                }
            }
        }
        component = it.next() orelse break;
    }

    // Validate the configured path itself independently of component string
    // spelling (for example a harmless trailing slash must not bypass the
    // ownership/mode check above).
    return validateSecureDirectory(io, target_path, expected_mode, required_owner);
}

fn validateSecureDirectory(
    io: std.Io,
    path: []const u8,
    expected_mode: std.posix.mode_t,
    required_owner: ?Owner,
) !Owner {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{
        .access_sub_paths = true,
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| {
        reportInsecureDirectory(path, expected_mode, err);
        return error.InsecureDirectory;
    };
    defer dir.close(io);
    const stat = statDirectory(dir) catch |err| {
        reportInsecureDirectory(path, expected_mode, err);
        return error.InsecureDirectory;
    };
    validateDirectoryAccess(stat, expected_mode) catch |err| {
        reportInsecureDirectory(path, expected_mode, err);
        return error.InsecureDirectory;
    };
    if (required_owner) |owner| {
        validateAnchoredDirectoryMetadata(stat, expected_mode, owner) catch |err| {
            reportInsecureDirectory(path, expected_mode, err);
            return error.InsecureDirectory;
        };
    }
    return .{ .uid = stat.st_uid, .gid = stat.st_gid };
}

fn validateAnchoredDirectoryMetadata(stat: c.struct_stat, expected_mode: std.posix.mode_t, owner: Owner) !void {
    try validateDirectoryMetadata(stat, expected_mode, owner.uid);
    if (expected_mode & 0o070 != 0 and stat.st_gid != owner.gid) return error.WrongGroup;
}

fn statDirectory(dir: std.Io.Dir) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(dir.handle, &stat) != 0) return error.MetadataUnavailable;
    return stat;
}

fn validateDirectoryType(stat: c.struct_stat) !void {
    if (!c.S_ISDIR(stat.st_mode)) return error.NotDirectory;
}

fn validateDirectoryMetadata(
    stat: c.struct_stat,
    expected_mode: std.posix.mode_t,
    expected_uid: c.uid_t,
) !void {
    try validateDirectoryType(stat);
    if (stat.st_uid != expected_uid) return error.WrongOwner;
    if (stat.st_mode & 0o7777 != expected_mode) return error.WrongMode;
}

fn validateDirectoryAccess(stat: c.struct_stat, expected_mode: std.posix.mode_t) !void {
    try validateDirectoryType(stat);
    if (stat.st_mode & 0o7777 != expected_mode) return error.WrongMode;
    if (stat.st_uid == c.geteuid()) return;

    // A foreign-owned configured directory is trusted only when its exact
    // policy grants full directory access to this caller. The directory's
    // owner and group then become the trust anchor for children.
    if (expected_mode & 0o007 == 0o007) return;
    if (expected_mode & 0o070 != 0o070) return error.WrongOwner;
    if (!callerInGroup(stat.st_gid)) return error.WrongOwner;
}

fn callerInGroup(gid: c.gid_t) bool {
    if (c.getegid() == gid) return true;
    const count = c.getgroups(0, null);
    if (count <= 0) return false;

    // Supplementary group counts are normally small. Refuse an implausible
    // result instead of allocating from configuration parsing.
    var groups: [256]c.gid_t = undefined;
    if (count > groups.len) return false;
    const actual = c.getgroups(count, &groups);
    if (actual != count) return false;
    for (groups[0..@intCast(actual)]) |member| {
        if (member == gid) return true;
    }
    return false;
}

fn parseEnvMode(io: std.Io, name: []const u8, default_mode: std.posix.mode_t) !std.posix.mode_t {
    const value = lib_posix.getenv(name) orelse return default_mode;
    return parseMode(value) catch |err| {
        reportInvalidMode(io, name, value);
        return err;
    };
}

fn parseMode(value: []const u8) !std.posix.mode_t {
    if (value.len == 0) return error.InvalidMode;

    var mode: u16 = 0;
    for (value) |digit| {
        if (digit < '0' or digit > '7') return error.InvalidMode;
        mode = mode * 8 + (digit - '0');
        if (mode > 0o777) return error.ModeOutOfRange;
    }
    return @intCast(mode);
}

pub fn socketMode(dir_mode: std.posix.mode_t) std.posix.mode_t {
    return dir_mode & 0o666;
}

fn reportInvalidMode(io: std.Io, name: []const u8, value: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    w.interface.print(
        "error: invalid {s} value \"{s}\"; expected an octal permission mode from 0000 through 0777\n",
        .{ name, value },
    ) catch {};
    w.interface.flush() catch {};
}

fn reportInsecureDirectory(path: []const u8, expected_mode: std.posix.mode_t, err: anyerror) void {
    std.debug.print(
        "error: insecure zmx directory \"{s}\" ({s}); use a real directory with the intended service owner/group and exact mode, then run: chmod {o} \"{s}\"\n",
        .{ path, @errorName(err), expected_mode, path },
    );
}

test "directory metadata validation rejects foreign, wrong-mode, and wrong-type metadata" {
    var stat = std.mem.zeroes(c.struct_stat);
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFDIR | 0o700;
    stat.st_gid = c.getegid();
    try validateDirectoryMetadata(stat, default_dir_mode, c.geteuid());

    stat.st_uid = c.geteuid() + 1;
    try std.testing.expectError(error.WrongOwner, validateDirectoryMetadata(stat, default_dir_mode, c.geteuid()));
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFDIR | 0o755;
    try std.testing.expectError(error.WrongMode, validateDirectoryMetadata(stat, default_dir_mode, c.geteuid()));
    stat.st_mode = c.S_IFREG | 0o700;
    try std.testing.expectError(error.NotDirectory, validateDirectoryMetadata(stat, default_dir_mode, c.geteuid()));
}

test "foreign directory owners require explicit group or world directory access" {
    var stat = std.mem.zeroes(c.struct_stat);
    stat.st_uid = c.geteuid() + 1;
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFDIR | 0o770;
    try validateDirectoryAccess(stat, 0o770);

    stat.st_mode = c.S_IFDIR | 0o700;
    try std.testing.expectError(error.WrongOwner, validateDirectoryAccess(stat, 0o700));
    stat.st_mode = c.S_IFDIR | 0o707;
    try validateDirectoryAccess(stat, 0o707);
}

test "anchored child directories must match the parent owner and group" {
    const owner: Owner = .{ .uid = c.geteuid(), .gid = c.getegid() };
    var stat = std.mem.zeroes(c.struct_stat);
    stat.st_uid = owner.uid;
    stat.st_gid = owner.gid;
    stat.st_mode = c.S_IFDIR | 0o770;
    try validateAnchoredDirectoryMetadata(stat, 0o770, owner);

    stat.st_uid += 1;
    try std.testing.expectError(error.WrongOwner, validateAnchoredDirectoryMetadata(stat, 0o770, owner));
    stat.st_uid = owner.uid;
    stat.st_gid += 1;
    try std.testing.expectError(error.WrongGroup, validateAnchoredDirectoryMetadata(stat, 0o770, owner));

    stat.st_mode = c.S_IFDIR | 0o700;
    try validateAnchoredDirectoryMetadata(stat, 0o700, owner);
}

test "nested log namespace detection tolerates trailing separators" {
    try std.testing.expect(isDirectChild("/srv/zmx", "/srv/zmx/logs"));
    try std.testing.expect(isDirectChild("/srv/zmx/", "/srv/zmx//logs"));
    try std.testing.expect(!isDirectChild("/srv/zmx", "/srv/zmx-other/logs"));
    try std.testing.expect(!isDirectChild("/srv/zmx", "/srv/zmx/logs/nested"));
}

test "permission mode parsing accepts octal values and rejects malformed or out-of-range values" {
    try std.testing.expectEqual(@as(std.posix.mode_t, 0), try parseMode("0"));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), try parseMode("0700"));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o770), try parseMode("770"));

    inline for (&.{ "", "8", "0o700", "700x", "-1" }) |value| {
        try std.testing.expectError(error.InvalidMode, parseMode(value));
    }
    inline for (&.{ "1000", "7777" }) |value| {
        try std.testing.expectError(error.ModeOutOfRange, parseMode(value));
    }
}

test "permission mode defaults and socket derivation" {
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o700), default_dir_mode);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), default_log_mode);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), socketMode(default_dir_mode));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o660), socketMode(0o770));
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o644), socketMode(0o755));
}
