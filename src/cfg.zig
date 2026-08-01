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

const directory_mode: std.Io.Dir.Permissions = .fromMode(0o700);
const directory_mode_bits: std.posix.mode_t = 0o700;

socket_dir: []const u8,
log_dir: []const u8,
max_scrollback: usize = 10_000_000,

pub fn init(alloc: std.mem.Allocator, io: std.Io) !Cfg {
    if (lib_posix.getenv("ZMX_DIR_MODE") != null) {
        reportDisabledMode(io, "ZMX_DIR_MODE");
        return error.ConfigurableModesDisabled;
    }
    if (lib_posix.getenv("ZMX_LOG_MODE") != null) {
        reportDisabledMode(io, "ZMX_LOG_MODE");
        return error.ConfigurableModesDisabled;
    }

    const socket_dir = try socketDir(alloc);
    errdefer alloc.free(socket_dir);
    const log_dir = try logDir(alloc);
    errdefer alloc.free(log_dir);

    var cfg = Cfg{
        .socket_dir = socket_dir,
        .log_dir = log_dir,
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
    try mkdirAll(io, self.socket_dir);
    try mkdirAll(io, self.log_dir);
}

fn mkdirAll(io: std.Io, sub_dir_path: []const u8) !void {
    var it = std.fs.path.componentIterator(sub_dir_path);
    var component = it.last() orelse return error.BadPathName;
    while (true) {
        var existing = false;
        std.Io.Dir.createDirAbsolute(io, component.path, directory_mode) catch |err| switch (err) {
            error.PathAlreadyExists => {
                existing = true;
                var dir = std.Io.Dir.openDirAbsolute(io, component.path, .{
                    .access_sub_paths = true,
                    .iterate = true,
                    .follow_symlinks = false,
                }) catch |open_err| {
                    reportInsecureDirectory(component.path, open_err);
                    return error.InsecureDirectory;
                };
                defer dir.close(io);
                const stat = statDirectory(dir) catch |stat_err| {
                    reportInsecureDirectory(component.path, stat_err);
                    return error.InsecureDirectory;
                };

                if (component.path.len == sub_dir_path.len) {
                    validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()) catch |validate_err| {
                        reportInsecureDirectory(component.path, validate_err);
                        return error.InsecureDirectory;
                    };
                } else {
                    // System/user-owned parents such as /tmp and $HOME are not
                    // zmx directories, but must still be real directories.
                    validateDirectoryType(stat) catch |validate_err| {
                        reportInsecureDirectory(component.path, validate_err);
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
                reportInsecureDirectory(component.path, err);
                return error.InsecureDirectory;
            };
            defer dir.close(io);
            dir.setPermissions(io, directory_mode) catch |err| {
                reportInsecureDirectory(component.path, err);
                return error.InsecureDirectory;
            };
            const stat = statDirectory(dir) catch |err| {
                reportInsecureDirectory(component.path, err);
                return error.InsecureDirectory;
            };
            validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()) catch |err| {
                reportInsecureDirectory(component.path, err);
                return error.InsecureDirectory;
            };
        }
        component = it.next() orelse break;
    }

    // Validate the configured path itself independently of component string
    // spelling (for example a harmless trailing slash must not bypass the
    // ownership/mode check above).
    try validateSecureDirectory(io, sub_dir_path);
}

fn validateSecureDirectory(io: std.Io, path: []const u8) !void {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{
        .access_sub_paths = true,
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| {
        reportInsecureDirectory(path, err);
        return error.InsecureDirectory;
    };
    defer dir.close(io);
    const stat = statDirectory(dir) catch |err| {
        reportInsecureDirectory(path, err);
        return error.InsecureDirectory;
    };
    validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()) catch |err| {
        reportInsecureDirectory(path, err);
        return error.InsecureDirectory;
    };
}

fn statDirectory(dir: std.Io.Dir) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(dir.handle, &stat) != 0) return error.MetadataUnavailable;
    return stat;
}

fn validateDirectoryType(stat: c.struct_stat) !void {
    if (!c.S_ISDIR(stat.st_mode)) return error.NotDirectory;
}

fn validateDirectoryMetadata(stat: c.struct_stat, expected_mode: std.posix.mode_t, expected_uid: c.uid_t) !void {
    try validateDirectoryType(stat);
    if (stat.st_uid != expected_uid) return error.WrongOwner;
    if (stat.st_mode & 0o7777 != expected_mode) return error.WrongMode;
}

fn reportDisabledMode(io: std.Io, name: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    const requirement = if (std.mem.eql(u8, name, "ZMX_LOG_MODE"))
        "logs are fixed at mode 600"
    else
        "directories are fixed at mode 700";
    w.interface.print(
        "error: {s} is no longer supported; unset {s} ({s})\n",
        .{ name, name, requirement },
    ) catch {};
    w.interface.flush() catch {};
}

fn reportInsecureDirectory(path: []const u8, err: anyerror) void {
    std.debug.print(
        "error: insecure zmx directory \"{s}\" ({s}); use a real directory, then run: chmod 700 \"{s}\" && chown {d} \"{s}\"\n",
        .{ path, @errorName(err), path, c.geteuid(), path },
    );
}

test "directory metadata validation rejects foreign, wrong-mode, and wrong-type metadata" {
    var stat = std.mem.zeroes(c.struct_stat);
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFDIR | 0o700;
    try validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid());

    stat.st_uid = c.geteuid() + 1;
    try std.testing.expectError(error.WrongOwner, validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()));
    stat.st_uid = c.geteuid();
    stat.st_mode = c.S_IFDIR | 0o755;
    try std.testing.expectError(error.WrongMode, validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()));
    stat.st_mode = c.S_IFREG | 0o700;
    try std.testing.expectError(error.NotDirectory, validateDirectoryMetadata(stat, directory_mode_bits, c.geteuid()));
}
