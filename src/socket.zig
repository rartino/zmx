const std = @import("std");
const Cfg = @import("cfg.zig");
const lib_posix = @import("posix.zig");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub fn getSeshPrefix() []const u8 {
    return lib_posix.getenv("ZMX_SESSION_PREFIX") orelse "";
}

pub fn getSeshNameFromEnv() []const u8 {
    return lib_posix.getenv("ZMX_SESSION") orelse "";
}

pub fn getSeshName(alloc: std.mem.Allocator, sesh: []const u8) ![]const u8 {
    const prefix = getSeshPrefix();
    if (prefix.len == 0 and sesh.len == 0) {
        return error.SessionNameRequired;
    }
    const full = try std.fmt.allocPrint(alloc, "{s}{s}", .{ prefix, sesh });
    // Session names become filenames under socket_dir. Rejecting path
    // separators and dot-dot prevents socket creation and stale-socket
    // deletion from operating outside that directory.
    if (std.mem.indexOfScalar(u8, full, '/') != null or
        std.mem.indexOfScalar(u8, full, 0) != null or
        std.mem.eql(u8, full, ".") or std.mem.eql(u8, full, "..") or
        std.mem.eql(u8, full, "logs"))
    {
        alloc.free(full);
        return error.InvalidSessionName;
    }
    return full;
}

pub fn resolveSessionOrEnv(alloc: std.mem.Allocator, io: std.Io, session_name: ?[]const u8) ![]const u8 {
    const sesh_env = getSeshNameFromEnv();
    const raw = if (session_name) |name|
        if (std.mem.eql(u8, name, ".")) blk: {
            if (sesh_env.len > 0) break :blk sesh_env;
            var buf: [4096]u8 = undefined;
            var w = std.Io.File.stderr().writer(io, &buf);
            w.interface.print("error: \".\" requires ZMX_SESSION (are you inside a zmx session?)\n", .{}) catch {};
            w.interface.flush() catch {};
            return error.SessionNameRequired;
        } else name
    else if (sesh_env.len > 0)
        sesh_env
    else {
        return error.SessionNameRequired;
    };
    return getSeshName(alloc, raw);
}

pub const SessionMatch = struct {
    name: []const u8,
    is_prefix: bool,

    pub fn matches(self: SessionMatch, session_name: []const u8) bool {
        if (self.is_prefix) return std.mem.startsWith(u8, session_name, self.name);
        return std.mem.eql(u8, session_name, self.name);
    }
};

pub fn parseSessionArg(alloc: std.mem.Allocator, raw: []const u8) !SessionMatch {
    if (raw.len > 0 and raw[raw.len - 1] == '*') {
        const name = try getSeshName(alloc, raw[0 .. raw.len - 1]);
        return .{ .name = name, .is_prefix = true };
    }
    const name = try getSeshName(alloc, raw);
    return .{ .name = name, .is_prefix = false };
}

pub fn sessionConnect(sesh: []const u8, expected_mode: std.posix.mode_t, owner: Cfg.Owner) !i32 {
    const stat = statPath(sesh) catch |err| {
        if (err != error.FileNotFound) reportInsecureSocket(sesh, expected_mode, owner, err);
        return err;
    };
    validateSocketMetadata(stat, owner, expected_mode) catch |err| {
        reportInsecureSocket(sesh, expected_mode, owner, err);
        return error.InsecureSocket;
    };

    var unix_addr = try lib_posix.initUnix(sesh);
    const socket_fd = try lib_posix.socket(lib_posix.AF.UNIX, lib_posix.SOCK.STREAM | lib_posix.SOCK.CLOEXEC, 0);
    errdefer lib_posix.close(socket_fd);
    try lib_posix.connect(socket_fd, &unix_addr.any, unix_addr.getOsSockLen());
    return socket_fd;
}

pub fn cleanupStaleSocket(
    io: std.Io,
    dir: std.Io.Dir,
    dir_path: []const u8,
    session_name: []const u8,
    expected_mode: std.posix.mode_t,
    owner: Cfg.Owner,
) void {
    const stat = statAt(dir, session_name) catch |err| {
        if (err != error.FileNotFound) {
            std.log.warn("refusing stale socket cleanup session={s} err={s}", .{ session_name, @errorName(err) });
        }
        return;
    };
    validateSocketMetadata(stat, owner, expected_mode) catch |err| {
        reportInsecureSocketEntry(dir_path, session_name, expected_mode, owner, err);
        return;
    };

    std.log.warn("stale socket found, cleaning up session={s}", .{session_name});
    dir.deleteFile(io, session_name) catch |err| {
        std.log.warn("failed to delete stale socket err={s}", .{@errorName(err)});
    };
}

pub fn sessionExists(
    io: std.Io,
    dir: std.Io.Dir,
    dir_path: []const u8,
    name: []const u8,
    expected_mode: std.posix.mode_t,
    owner: Cfg.Owner,
) !bool {
    _ = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| {
        switch (err) {
            error.FileNotFound => return false,
            else => return err,
        }
    };

    const stat = try statAt(dir, name);
    validateSocketMetadata(stat, owner, expected_mode) catch |err| {
        reportInsecureSocketEntry(dir_path, name, expected_mode, owner, err);
        return error.InsecureSocket;
    };
    return true;
}

pub fn createSocket(sesh: []const u8, expected_mode: std.posix.mode_t, owner: Cfg.Owner) !lib_posix.socket_t {
    // AF.UNIX: Unix domain socket for local IPC with client processes
    // SOCK.STREAM: Reliable, bidirectional communication
    // SOCK.NONBLOCK: Set socket to non-blocking
    const fd = try lib_posix.socket(
        lib_posix.AF.UNIX,
        lib_posix.SOCK.STREAM | lib_posix.SOCK.NONBLOCK | lib_posix.SOCK.CLOEXEC,
        0,
    );
    errdefer lib_posix.close(fd);
    var path_buf = try pathZ(sesh);
    var bound = false;
    errdefer {
        if (bound) _ = c.unlink(path_buf[0..sesh.len :0]);
    }

    var unix_addr = try lib_posix.initUnix(sesh);
    // Unix socket nodes are created from a 0777 base mode. Set the final mode
    // as part of bind so a group-writable containing directory never exposes
    // a pathname-based chmod race. createSocket runs before daemon threads or
    // child processes exist, and restores the process umask immediately.
    const old_umask = c.umask(@intCast((~expected_mode) & 0o777));
    defer _ = c.umask(old_umask);
    try lib_posix.bind(fd, &unix_addr.any, unix_addr.getOsSockLen());
    bound = true;

    const stat = statPath(sesh) catch |err| {
        reportInsecureSocket(sesh, expected_mode, owner, err);
        return error.InsecureSocket;
    };
    validateSocketMetadata(stat, owner, expected_mode) catch |err| {
        reportInsecureSocket(sesh, expected_mode, owner, err);
        return error.InsecureSocket;
    };
    try lib_posix.listen(fd, 128);

    // The errdefer above owns the newly-bound path until listen succeeds.
    bound = false;
    return fd;
}

fn pathZ(path: []const u8) ![std.c.PATH_MAX + 1]u8 {
    var path_buf: [std.c.PATH_MAX + 1]u8 = undefined;
    if (path.len >= path_buf.len) return error.NameTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    return path_buf;
}

fn statPath(path: []const u8) !c.struct_stat {
    var path_buf = try pathZ(path);
    var stat: c.struct_stat = undefined;
    const rc = c.fstatat(c.AT_FDCWD, path_buf[0..path.len :0], &stat, c.AT_SYMLINK_NOFOLLOW);
    if (rc == 0) return stat;
    return if (std.c.errno(rc) == .NOENT) error.FileNotFound else error.MetadataUnavailable;
}

fn statAt(dir: std.Io.Dir, name: []const u8) !c.struct_stat {
    var path_buf = try pathZ(name);
    var stat: c.struct_stat = undefined;
    const rc = c.fstatat(dir.handle, path_buf[0..name.len :0], &stat, c.AT_SYMLINK_NOFOLLOW);
    if (rc == 0) return stat;
    return if (std.c.errno(rc) == .NOENT) error.FileNotFound else error.MetadataUnavailable;
}

fn validateSocketMetadata(stat: c.struct_stat, owner: Cfg.Owner, expected_mode: std.posix.mode_t) !void {
    if (!c.S_ISSOCK(stat.st_mode)) return error.NotUnixSocket;
    if (stat.st_uid != owner.uid) return error.WrongOwner;
    if (expected_mode & 0o070 != 0 and stat.st_gid != owner.gid) return error.WrongGroup;
    if (stat.st_mode & 0o7777 != expected_mode) return error.WrongMode;
}

fn reportInsecureSocket(path: []const u8, expected_mode: std.posix.mode_t, owner: Cfg.Owner, err: anyerror) void {
    std.debug.print(
        "error: insecure zmx socket \"{s}\" ({s}); remove a symlink/wrong-type path, or run: chmod {o} \"{s}\" && chown {d}:{d} \"{s}\"\n",
        .{ path, @errorName(err), expected_mode, path, owner.uid, owner.gid, path },
    );
}

fn reportInsecureSocketEntry(
    dir_path: []const u8,
    name: []const u8,
    expected_mode: std.posix.mode_t,
    owner: Cfg.Owner,
    err: anyerror,
) void {
    std.debug.print(
        "error: insecure zmx socket \"{s}/{s}\" ({s}); remove a symlink/wrong-type path, or run: chmod {o} \"{s}/{s}\" && chown {d}:{d} \"{s}/{s}\"\n",
        .{ dir_path, name, @errorName(err), expected_mode, dir_path, name, owner.uid, owner.gid, dir_path, name },
    );
}

/// Maximum number of usable bytes in a Unix domain socket path.
/// Derived from the platform's sockaddr_un.path field, minus 1 for the
/// required null terminator.
pub const max_socket_path_len: usize = @typeInfo(
    @TypeOf(@as(lib_posix.sockaddr.un, undefined).path),
).array.len - 1;

pub fn getSocketPath(
    alloc: std.mem.Allocator,
    socket_dir: []const u8,
    session_name: []const u8,
) error{ NameTooLong, OutOfMemory }![]const u8 {
    const dir = socket_dir;
    const path_len = dir.len + 1 + session_name.len;
    if (path_len > max_socket_path_len) return error.NameTooLong;
    const fname = try alloc.alloc(u8, path_len);
    @memcpy(fname[0..dir.len], dir);
    @memcpy(fname[dir.len .. dir.len + 1], "/");
    @memcpy(fname[dir.len + 1 ..], session_name);
    return fname;
}

/// Validate a session name at the point where a peer asks to switch to it.
/// Keep this check allocation-free and consistent with getSeshName so a
/// caller cannot make the daemon address a path outside socket_dir.
pub fn validateCanonicalSessionName(socket_dir: []const u8, session_name: []const u8) !void {
    if (session_name.len == 0 or
        std.mem.indexOfScalar(u8, session_name, '/') != null or
        std.mem.indexOfScalar(u8, session_name, 0) != null or
        std.mem.eql(u8, session_name, ".") or
        std.mem.eql(u8, session_name, "..") or
        std.mem.eql(u8, session_name, "logs"))
    {
        return error.InvalidSessionName;
    }
    const max_len = maxSessionNameLen(socket_dir) orelse return error.NameTooLong;
    if (session_name.len > max_len) return error.NameTooLong;
}

pub fn printSessionNameTooLong(io: std.Io, session_name: []const u8, socket_dir: []const u8) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    if (maxSessionNameLen(socket_dir)) |max_len| {
        w.interface.print(
            "error: session name is too long ({d} bytes, max {d} for socket directory \"{s}\")\n",
            .{ session_name.len, max_len, socket_dir },
        ) catch {};
    } else {
        w.interface.print(
            "error: socket directory path is too long (\"{s}\")\n",
            .{socket_dir},
        ) catch {};
    }
    w.interface.flush() catch {};
}

/// Returns the maximum session name length for a given socket directory,
/// or null if the socket directory itself is already too long.
pub fn maxSessionNameLen(socket_dir: []const u8) ?usize {
    // path = socket_dir + "/" + session_name
    const overhead = socket_dir.len + 1;
    if (overhead >= max_socket_path_len) return null;
    return max_socket_path_len - overhead;
}

test "max_socket_path_len matches platform sockaddr_un" {
    const path_field_len = @typeInfo(
        @TypeOf(@as(lib_posix.sockaddr.un, undefined).path),
    ).array.len;
    try std.testing.expectEqual(path_field_len - 1, max_socket_path_len);
    try std.testing.expect(max_socket_path_len > 0);
}

test "canonical session validation rejects malicious and overlong switch targets" {
    try validateCanonicalSessionName("/tmp/zmx", "dev.nested");
    inline for (&.{ "", ".", "..", "logs", "a/b", "a\x00b" }) |name| {
        try std.testing.expectError(error.InvalidSessionName, validateCanonicalSessionName("/tmp/zmx", name));
    }

    const max_len = maxSessionNameLen("/tmp/zmx").?;
    const overlong = try std.testing.allocator.alloc(u8, max_len + 1);
    defer std.testing.allocator.free(overlong);
    @memset(overlong, 'x');
    try std.testing.expectError(error.NameTooLong, validateCanonicalSessionName("/tmp/zmx", overlong));
}

test "socket metadata validation rejects foreign, wrong-mode, and wrong-type metadata" {
    var stat = std.mem.zeroes(c.struct_stat);
    const owner: Cfg.Owner = .{ .uid = c.geteuid(), .gid = c.getegid() };
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFSOCK | 0o600;
    try validateSocketMetadata(stat, owner, 0o600);

    stat.st_uid = c.geteuid() + 1;
    try std.testing.expectError(error.WrongOwner, validateSocketMetadata(stat, owner, 0o600));
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid() + 1;
    stat.st_mode = c.S_IFSOCK | 0o660;
    try std.testing.expectError(error.WrongGroup, validateSocketMetadata(stat, owner, 0o660));
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFSOCK | 0o666;
    try std.testing.expectError(error.WrongMode, validateSocketMetadata(stat, owner, 0o600));
    stat.st_mode = c.S_IFREG | 0o600;
    try std.testing.expectError(error.NotUnixSocket, validateSocketMetadata(stat, owner, 0o600));
}

test "socket metadata validation accepts the configured mode exactly" {
    var stat = std.mem.zeroes(c.struct_stat);
    const owner: Cfg.Owner = .{ .uid = c.geteuid(), .gid = c.getegid() };
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFSOCK | 0o660;
    try validateSocketMetadata(stat, owner, 0o660);
    try std.testing.expectError(error.WrongMode, validateSocketMetadata(stat, owner, 0o600));
}

test "getSocketPath succeeds for paths within limit" {
    const alloc = std.testing.allocator;
    const result = try getSocketPath(alloc, "/tmp/zmx", "mysession");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("/tmp/zmx/mysession", result);
}

test "getSocketPath returns NameTooLong when path exceeds limit" {
    const alloc = std.testing.allocator;
    const dir = [_]u8{'d'} ** (max_socket_path_len - 2);
    const dir_slice: []const u8 = &dir;

    const ok = try getSocketPath(alloc, dir_slice, "x");
    defer alloc.free(ok);
    try std.testing.expectEqual(max_socket_path_len, ok.len);

    const err = getSocketPath(alloc, dir_slice, "xx");
    try std.testing.expectError(error.NameTooLong, err);
}

test "getSocketPath returns NameTooLong for empty dir with oversized name" {
    const alloc = std.testing.allocator;
    const name = [_]u8{'n'} ** (max_socket_path_len);
    const name_slice: []const u8 = &name;
    const err = getSocketPath(alloc, "", name_slice);
    try std.testing.expectError(error.NameTooLong, err);
}

test "maxSessionNameLen computes correct dynamic limit" {
    const short_dir = "/tmp/zmx";
    const short_max = maxSessionNameLen(short_dir).?;
    try std.testing.expectEqual(max_socket_path_len - short_dir.len - 1, short_max);

    const full_dir = [_]u8{'f'} ** max_socket_path_len;
    const full_dir_slice: []const u8 = &full_dir;
    try std.testing.expectEqual(@as(?usize, null), maxSessionNameLen(full_dir_slice));

    const tight_dir = [_]u8{'t'} ** (max_socket_path_len - 2);
    const tight_dir_slice: []const u8 = &tight_dir;
    try std.testing.expectEqual(@as(?usize, 1), maxSessionNameLen(tight_dir_slice));
}

test "getSocketPath boundary: name fills exactly to limit" {
    const alloc = std.testing.allocator;
    const dir = "/tmp/zmx";
    const max_name_len = maxSessionNameLen(dir).?;

    const name_at_limit = try alloc.alloc(u8, max_name_len);
    defer alloc.free(name_at_limit);
    @memset(name_at_limit, 'a');

    const path = try getSocketPath(alloc, dir, name_at_limit);
    defer alloc.free(path);
    try std.testing.expectEqual(max_socket_path_len, path.len);

    const name_over_limit = try alloc.alloc(u8, max_name_len + 1);
    defer alloc.free(name_over_limit);
    @memset(name_over_limit, 'b');

    try std.testing.expectError(error.NameTooLong, getSocketPath(alloc, dir, name_over_limit));
}
