const std = @import("std");
const Cfg = @import("cfg.zig");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

pub var log_system = LogSystem{};

pub fn zmxLogFn(
    comptime level: std.log.Level,
    comptime scope: anytype,
    comptime format: []const u8,
    args: anytype,
) void {
    log_system.log(level, scope, format, args) catch {};
}

/// Validate or securely create a log file before a caller crosses a fork or
/// otherwise loses the initiating user's stderr. The same open path is used by
/// LogSystem.init and rotation; this function only releases the validated file.
pub fn preflight(io: std.Io, path: []const u8, expected_mode: std.posix.mode_t, owner: Cfg.Owner) !void {
    const file = try openValidatedOrCreate(io, path, expected_mode, owner);
    file.close(io);
}

pub const LogSystem = struct {
    file: ?std.Io.File = null,
    mutex: std.Io.Mutex = .init,
    current_size: u64 = 0,
    max_size: u64 = 2 * 1024 * 1024, // 2MB
    path: []const u8 = "",
    mode: std.posix.mode_t = 0o600,
    owner: Cfg.Owner = .{ .uid = 0, .gid = 0 },
    io: std.Io = undefined,

    pub fn init(self: *LogSystem, io: std.Io, path: []const u8, mode: std.posix.mode_t, owner: Cfg.Owner) !void {
        self.io = io;
        self.path = path;
        self.mode = mode;
        self.owner = owner;

        const file = try openValidatedOrCreate(io, path, mode, owner);
        errdefer file.close(io);

        const end_pos = try std.Io.File.length(file, io);
        var buf: [1]u8 = undefined;
        var w = std.Io.File.writer(file, io, &buf);
        try w.seekTo(end_pos);
        self.current_size = end_pos;
        self.file = file;
    }

    pub fn deinit(self: *LogSystem) void {
        if (self.file) |f| std.Io.File.close(f, self.io);
        self.file = null;
    }

    pub fn log(
        self: *LogSystem,
        comptime level: std.log.Level,
        comptime scope: anytype,
        comptime format: []const u8,
        args: anytype,
    ) !void {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        if (self.file == null) {
            std.log.defaultLog(level, scope, format, args);
            return;
        }

        if (self.current_size >= self.max_size) {
            self.wipe() catch |err| {
                std.debug.print("Log wipe failed: {s}\n", .{@errorName(err)});
            };
        }

        const now: std.Io.Timestamp = .now(self.io, .real);
        const prefix = "[{d}] [{s}] ({s}): ";
        const scope_name = @tagName(scope);
        const level_name = level.asText();

        const prefix_args = .{
            now,
            level_name,
            scope_name,
        };

        if (self.file) |f| {
            const prefix_len = std.fmt.count(prefix, prefix_args);
            const msg_len = std.fmt.count(format, args);
            const newline_len = 1;
            const total_len = prefix_len + msg_len + newline_len;
            self.current_size += total_len;

            var buf: [4096]u8 = undefined;
            var w = f.writerStreaming(self.io, &buf);
            std.Io.Writer.print(&w.interface, prefix ++ format ++ "\n", prefix_args ++ args) catch {};
            w.interface.flush() catch {};
        }
    }

    fn wipe(self: *LogSystem) !void {
        if (self.file) |f| {
            std.Io.File.close(f, self.io);
            self.file = null;
        }

        var file = try openValidatedOrCreate(self.io, self.path, self.mode, self.owner);
        errdefer file.close(self.io);
        try file.setLength(self.io, 0);
        self.file = file;
        self.current_size = 0;
    }
};

fn openValidatedOrCreate(
    io: std.Io,
    path: []const u8,
    expected_mode: std.posix.mode_t,
    owner: Cfg.Owner,
) !std.Io.File {
    const permissions: std.Io.File.Permissions = .fromMode(@intCast(expected_mode));
    while (true) {
        const stat = statPath(path) catch |err| switch (err) {
            error.FileNotFound => {
                // A group client may use service-owned logs but must not
                // establish a new trust anchor under its own UID.
                if (c.geteuid() != owner.uid or
                    (expected_mode & 0o070 != 0 and c.getegid() != owner.gid))
                {
                    reportInsecureLog(path, expected_mode, owner, error.WrongOwner);
                    return error.InsecureLogFile;
                }
                const file = std.Io.Dir.createFileAbsolute(io, path, .{
                    .read = true,
                    .truncate = false,
                    .exclusive = true,
                    .permissions = permissions,
                }) catch |create_err| switch (create_err) {
                    error.PathAlreadyExists => continue,
                    else => return create_err,
                };
                errdefer file.close(io);
                // File creation honors umask; the newly-created file may be
                // repaired before it is exposed to the rest of zmx.
                try file.setPermissions(io, permissions);
                const created_stat = try statFileHandle(file);
                validateLogMetadata(created_stat, owner, expected_mode) catch |validate_err| {
                    reportInsecureLog(path, expected_mode, owner, validate_err);
                    return error.InsecureLogFile;
                };
                return file;
            },
            else => |e| return e,
        };

        validateLogMetadata(stat, owner, expected_mode) catch |validate_err| {
            reportInsecureLog(path, expected_mode, owner, validate_err);
            return error.InsecureLogFile;
        };

        const file = std.Io.Dir.openFileAbsolute(io, path, .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        }) catch |err| {
            reportInsecureLog(path, expected_mode, owner, err);
            return error.InsecureLogFile;
        };
        errdefer file.close(io);
        const opened_stat = statFileHandle(file) catch |err| {
            reportInsecureLog(path, expected_mode, owner, err);
            return error.InsecureLogFile;
        };
        validateLogMetadata(opened_stat, owner, expected_mode) catch |validate_err| {
            reportInsecureLog(path, expected_mode, owner, validate_err);
            return error.InsecureLogFile;
        };
        return file;
    }
}

fn statFileHandle(file: std.Io.File) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(file.handle, &stat) != 0) return error.MetadataUnavailable;
    return stat;
}

fn statPath(path: []const u8) !c.struct_stat {
    var path_buf: [std.c.PATH_MAX + 1]u8 = undefined;
    if (path.len >= path_buf.len) return error.NameTooLong;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    var stat: c.struct_stat = undefined;
    const rc = c.fstatat(c.AT_FDCWD, path_buf[0..path.len :0], &stat, c.AT_SYMLINK_NOFOLLOW);
    if (rc == 0) return stat;
    return if (std.c.errno(rc) == .NOENT) error.FileNotFound else error.MetadataUnavailable;
}

fn validateLogMetadata(stat: c.struct_stat, owner: Cfg.Owner, expected_mode: std.posix.mode_t) !void {
    if (!c.S_ISREG(stat.st_mode)) return error.NotRegularFile;
    if (stat.st_uid != owner.uid) return error.WrongOwner;
    if (expected_mode & 0o070 != 0 and stat.st_gid != owner.gid) return error.WrongGroup;
    if (stat.st_mode & 0o7777 != expected_mode) return error.WrongMode;
}

fn reportInsecureLog(path: []const u8, expected_mode: std.posix.mode_t, owner: Cfg.Owner, err: anyerror) void {
    std.debug.print(
        "error: insecure zmx log \"{s}\" ({s}); remove a symlink/wrong-type path, or run: chmod {o} \"{s}\" && chown {d}:{d} \"{s}\"\n",
        .{ path, @errorName(err), expected_mode, path, owner.uid, owner.gid, path },
    );
}

test "log metadata validation rejects foreign, wrong-mode, and wrong-type metadata" {
    var stat = std.mem.zeroes(c.struct_stat);
    const owner: Cfg.Owner = .{ .uid = c.geteuid(), .gid = c.getegid() };
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFREG | 0o600;
    try validateLogMetadata(stat, owner, 0o600);

    stat.st_uid = c.geteuid() + 1;
    try std.testing.expectError(error.WrongOwner, validateLogMetadata(stat, owner, 0o600));
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid() + 1;
    stat.st_mode = c.S_IFREG | 0o660;
    try std.testing.expectError(error.WrongGroup, validateLogMetadata(stat, owner, 0o660));
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFREG | 0o640;
    try std.testing.expectError(error.WrongMode, validateLogMetadata(stat, owner, 0o600));
    stat.st_mode = c.S_IFDIR | 0o600;
    try std.testing.expectError(error.NotRegularFile, validateLogMetadata(stat, owner, 0o600));
}

test "log metadata validation accepts the configured mode exactly" {
    var stat = std.mem.zeroes(c.struct_stat);
    const owner: Cfg.Owner = .{ .uid = c.geteuid(), .gid = c.getegid() };
    stat.st_uid = c.geteuid();
    stat.st_gid = c.getegid();
    stat.st_mode = c.S_IFREG | 0o660;
    try validateLogMetadata(stat, owner, 0o660);
    try std.testing.expectError(error.WrongMode, validateLogMetadata(stat, owner, 0o600));
}
