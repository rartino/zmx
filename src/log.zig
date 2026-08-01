const std = @import("std");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

const log_mode: std.Io.File.Permissions = .fromMode(0o600);
const log_mode_bits: std.posix.mode_t = 0o600;

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
pub fn preflight(io: std.Io, path: []const u8) !void {
    const file = try openValidatedOrCreate(io, path);
    file.close(io);
}

pub const LogSystem = struct {
    file: ?std.Io.File = null,
    mutex: std.Io.Mutex = .init,
    current_size: u64 = 0,
    max_size: u64 = 2 * 1024 * 1024, // 2MB
    path: []const u8 = "",
    io: std.Io = undefined,

    pub fn init(self: *LogSystem, io: std.Io, path: []const u8) !void {
        self.io = io;
        self.path = path;

        const file = try openValidatedOrCreate(io, path);
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

        var file = try openValidatedOrCreate(self.io, self.path);
        errdefer file.close(self.io);
        try file.setLength(self.io, 0);
        self.file = file;
        self.current_size = 0;
    }
};

fn openValidatedOrCreate(io: std.Io, path: []const u8) !std.Io.File {
    while (true) {
        const stat = statPath(path) catch |err| switch (err) {
            error.FileNotFound => {
                const file = std.Io.Dir.createFileAbsolute(io, path, .{
                    .read = true,
                    .truncate = false,
                    .exclusive = true,
                    .permissions = log_mode,
                }) catch |create_err| switch (create_err) {
                    error.PathAlreadyExists => continue,
                    else => return create_err,
                };
                errdefer file.close(io);
                // File creation honors umask; the newly-created file may be
                // repaired before it is exposed to the rest of zmx.
                try file.setPermissions(io, log_mode);
                const created_stat = try statFileHandle(file);
                validateLogMetadata(created_stat, c.geteuid()) catch |validate_err| {
                    reportInsecureLog(path, validate_err);
                    return error.InsecureLogFile;
                };
                return file;
            },
            else => |e| return e,
        };

        validateLogMetadata(stat, c.geteuid()) catch |validate_err| {
            reportInsecureLog(path, validate_err);
            return error.InsecureLogFile;
        };

        const file = std.Io.Dir.openFileAbsolute(io, path, .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        }) catch |err| {
            reportInsecureLog(path, err);
            return error.InsecureLogFile;
        };
        errdefer file.close(io);
        const opened_stat = statFileHandle(file) catch |err| {
            reportInsecureLog(path, err);
            return error.InsecureLogFile;
        };
        validateLogMetadata(opened_stat, c.geteuid()) catch |validate_err| {
            reportInsecureLog(path, validate_err);
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

fn validateLogMetadata(stat: c.struct_stat, expected_uid: c.uid_t) !void {
    if (!c.S_ISREG(stat.st_mode)) return error.NotRegularFile;
    if (stat.st_uid != expected_uid) return error.WrongOwner;
    if (stat.st_mode & 0o7777 != log_mode_bits) return error.WrongMode;
}

fn reportInsecureLog(path: []const u8, err: anyerror) void {
    std.debug.print(
        "error: insecure zmx log \"{s}\" ({s}); remove a symlink/wrong-type path, or run: chmod 600 \"{s}\" && chown {d} \"{s}\"\n",
        .{ path, @errorName(err), path, c.geteuid(), path },
    );
}

test "log metadata validation rejects foreign, wrong-mode, and wrong-type metadata" {
    var stat = std.mem.zeroes(c.struct_stat);
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFREG | 0o600;
    try validateLogMetadata(stat, c.geteuid());

    stat.st_uid = c.geteuid() + 1;
    try std.testing.expectError(error.WrongOwner, validateLogMetadata(stat, c.geteuid()));
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFREG | 0o640;
    try std.testing.expectError(error.WrongMode, validateLogMetadata(stat, c.geteuid()));
    stat.st_mode = c.S_IFDIR | 0o600;
    try std.testing.expectError(error.NotRegularFile, validateLogMetadata(stat, c.geteuid()));
}
