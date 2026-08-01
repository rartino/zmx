const std = @import("std");
const cross = @import("cross.zig");
const socket = @import("socket.zig");
const lib_posix = @import("posix.zig");
const test_c = if (@import("builtin").is_test) @cImport({
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
}) else struct {};

pub const Tag = enum(u8) {
    Input = 0,
    Output = 1,
    Resize = 2,
    Detach = 3,
    DetachAll = 4,
    Kill = 5,
    Info = 6,
    Init = 7,
    History = 8,
    Run = 9,
    Ack = 10,
    Switch = 11,
    Write = 12,
    TaskComplete = 13,
    LabelGet = 14,
    LabelSet = 15,
    LabelClear = 16,
    LabelData = 17,
    Send = 18,
    InputPolicy = 19,
    InputPolicyMismatch = 20,
    RequestRejected = 21,
    // Non-exhaustive because this enum comes from untrusted wire bytes.
    // Switches must safely handle `_` (unknown tag).
    _,
};

comptime {
    if (@typeInfo(Tag).@"enum".is_exhaustive) @compileError(
        "ipc.Tag must stay non-exhaustive so unknown wire tags are safely ignored",
    );
}

pub const Header = packed struct {
    tag: Tag,
    len: u32,
};

pub const Resize = packed struct {
    rows: u16,
    cols: u16,
    xpixel: u16 = 0,
    ypixel: u16 = 0,
};

pub const InputPolicy = packed struct {
    log_input: u8,

    pub fn init(log_input: bool) InputPolicy {
        return .{ .log_input = @intFromBool(log_input) };
    }

    pub fn value(self: InputPolicy) ?bool {
        return switch (self.log_input) {
            0 => false,
            1 => true,
            else => null,
        };
    }
};

pub const SwitchTarget = struct {
    log_input: bool,
    name: []const u8,
};

/// Switch wire payload: one policy byte followed by the canonical target
/// name. The policy is carried so the receiving terminal can acknowledge the
/// target daemon correctly; it does not alter either daemon.
pub fn parseSwitchTarget(payload: []const u8) !SwitchTarget {
    if (payload.len < 2) return error.InvalidSwitchTarget;
    const log_input = switch (payload[0]) {
        0 => false,
        1 => true,
        else => return error.InvalidSwitchTarget,
    };
    return .{ .log_input = log_input, .name = payload[1..] };
}

pub fn getTerminalSize(fd: i32) Resize {
    var ws: cross.c.struct_winsize = undefined;
    if (cross.c.ioctl(fd, cross.c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col, .xpixel = ws.ws_xpixel, .ypixel = ws.ws_ypixel };
    }
    return .{ .rows = 24, .cols = 120 };
}

pub const MAX_CMD_LEN = 256;
pub const MAX_CWD_LEN = 256;
pub const MAX_WRITE_CONTENT_LEN = 128 * 1024;
pub const MAX_WRITE_PATH_LEN = 4096;

/// Upper bounds keep one malformed local stream from growing a parser until
/// memory exhaustion. Write and History are intentionally larger than normal
/// control/input frames because those commands carry file and scrollback data.
pub fn maxPayloadLen(tag: Tag) usize {
    return switch (tag) {
        .History, .Output => 64 * 1024 * 1024,
        .Write => @sizeOf(u32) + MAX_WRITE_PATH_LEN + MAX_WRITE_CONTENT_LEN,
        else => 1024 * 1024,
    };
}

/// Frames received by a daemon are commands from a local client. They never
/// need the large History/Output response allowance used in the opposite
/// direction. Keep this limit separate so a peer cannot turn one large input
/// frame into a copy for every attached terminal.
pub fn maxClientPayloadLen(tag: Tag) usize {
    return switch (tag) {
        .Write => @sizeOf(u32) + MAX_WRITE_PATH_LEN + MAX_WRITE_CONTENT_LEN,
        else => 1024 * 1024,
    };
}

/// Frozen wire shape. Do NOT add fields; new stats use new `Tag` values.
/// This is an internal invariant for peers built from the same source.
pub const Info = extern struct {
    clients_len: u64,
    pid: i32,
    cmd_len: u16,
    cwd_len: u16,
    cmd: [MAX_CMD_LEN]u8,
    cwd: [MAX_CWD_LEN]u8,
    created_at: u64,
    task_ended_at: u64,
    task_exit_code: u8,
};

pub fn expectedLength(data: []const u8) ?usize {
    if (data.len < @sizeOf(Header)) return null;
    const header = std.mem.bytesToValue(Header, data[0..@sizeOf(Header)]);
    // header.len comes off the wire; widen to usize before adding so a
    // near-u32-max value can't wrap (panic in safe mode, UB in release).
    return @as(usize, @sizeOf(Header)) + @as(usize, header.len);
}

pub fn send(fd: i32, tag: Tag, data: []const u8) !void {
    if (data.len > maxPayloadLen(tag)) return error.FrameTooLarge;
    const header = Header{
        .tag = tag,
        .len = @intCast(data.len),
    };
    const header_bytes = std.mem.asBytes(&header);
    try writeAll(fd, header_bytes);
    if (data.len > 0) {
        try writeAll(fd, data);
    }
}

pub fn appendMessage(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    tag: Tag,
    data: []const u8,
) !void {
    if (data.len > maxPayloadLen(tag)) return error.FrameTooLarge;
    const header = Header{
        .tag = tag,
        .len = @intCast(data.len),
    };
    // Guarantee capacity for header + payload in one check to avoid
    // intermediate realloc between the two appends on the hot path.
    try list.ensureTotalCapacity(gpa, list.items.len + @sizeOf(Header) + data.len);
    list.appendSliceAssumeCapacity(std.mem.asBytes(&header));
    if (data.len > 0) {
        list.appendSliceAssumeCapacity(data);
    }
}

fn writeAll(fd: i32, data: []const u8) !void {
    var index: usize = 0;
    while (index < data.len) {
        const n = try lib_posix.write(fd, data[index..]);
        if (n == 0) return error.DiskQuota;
        index += n;
    }
}

pub const Message = struct {
    tag: Tag,
    data: []u8,

    pub fn deinit(self: Message, alloc: std.mem.Allocator) void {
        if (self.data.len > 0) {
            alloc.free(self.data);
        }
    }
};

pub const SocketMsg = struct {
    header: Header,
    payload: []const u8,
};

pub const SocketBuffer = struct {
    const Peer = enum { client, daemon };

    buf: std.ArrayList(u8),
    alloc: std.mem.Allocator,
    head: usize,
    peer: Peer,

    pub fn init(alloc: std.mem.Allocator) !SocketBuffer {
        return initForPeer(alloc, .client);
    }

    /// Initialize a buffer for responses sent by a trusted session daemon.
    /// History and terminal restoration can legitimately exceed command-size
    /// limits, while daemon ingress remains capped by `init` above.
    pub fn initFromDaemon(alloc: std.mem.Allocator) !SocketBuffer {
        return initForPeer(alloc, .daemon);
    }

    fn initForPeer(alloc: std.mem.Allocator, peer: Peer) !SocketBuffer {
        return .{
            .buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
            .alloc = alloc,
            .head = 0,
            .peer = peer,
        };
    }

    pub fn deinit(self: *SocketBuffer) void {
        self.buf.deinit(self.alloc);
    }

    /// Reads from fd into buffer.
    /// Returns number of bytes read.
    /// Propagates error.WouldBlock and other errors to caller.
    /// Returns 0 on EOF.
    pub fn read(self: *SocketBuffer, fd: i32) !usize {
        if (self.head > 0) {
            const remaining = self.buf.items.len - self.head;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[self.head..]);
                self.buf.items.len = remaining;
            } else {
                self.buf.clearRetainingCapacity();
            }
            self.head = 0;
        }

        try self.validatePendingHeader();

        var tmp: [4096]u8 = undefined;
        const n = try lib_posix.read(fd, &tmp);
        if (n > 0) {
            try self.buf.appendSlice(self.alloc, tmp[0..n]);
            try self.validatePendingHeader();
        }
        return n;
    }

    fn validatePendingHeader(self: *const SocketBuffer) !void {
        const available = self.buf.items[self.head..];
        if (available.len < @sizeOf(Header)) return;
        const header = std.mem.bytesToValue(Header, available[0..@sizeOf(Header)]);
        const limit = switch (self.peer) {
            .client => maxClientPayloadLen(header.tag),
            .daemon => maxPayloadLen(header.tag),
        };
        if (@as(usize, header.len) > limit) return error.FrameTooLarge;
    }

    /// Returns the next complete message or `null` when none available.
    /// `buf` is advanced automatically; caller keeps the returned slices
    /// valid until the following `next()` (or `deinit`).
    pub fn next(self: *SocketBuffer) ?SocketMsg {
        const available = self.buf.items[self.head..];
        const total = expectedLength(available) orelse return null;
        if (available.len < total) return null;

        const hdr = std.mem.bytesToValue(Header, available[0..@sizeOf(Header)]);
        const pay = available[@sizeOf(Header)..total];

        self.head += total;
        return .{ .header = hdr, .payload = pay };
    }
};

const ConnectError = error{
    ConnectionRefused,
    Unexpected,
};

/// Connect-only liveness check. Callers that don't read `Info` should use
/// this (not `probeSession`) so they survive `Info` shape changes.
pub fn connectSession(socket_path: []const u8) ConnectError!i32 {
    return socket.sessionConnect(socket_path) catch |err| switch (err) {
        error.ConnectionRefused => return error.ConnectionRefused,
        else => return error.Unexpected,
    };
}

/// Declare and confirm the immutable input-logging policy before this
/// connection sends any PTY-bound data. This is policy enforcement, not
/// protocol negotiation: all peers are expected to run the same build.
pub fn acknowledgeInputPolicy(
    alloc: std.mem.Allocator,
    fd: i32,
    log_input: bool,
) !SocketBuffer {
    const policy = InputPolicy.init(log_input);
    try send(fd, .InputPolicy, std.mem.asBytes(&policy));

    var read_buf = try SocketBuffer.initFromDaemon(alloc);
    errdefer read_buf.deinit();

    while (true) {
        var header: Header = undefined;
        try readPolicyBytes(fd, std.mem.asBytes(&header));
        const payload_len: usize = @intCast(header.len);

        // Policy responses and any raced PTY Output frames are small. Refuse
        // an implausible peer frame instead of allocating an attacker-chosen
        // u32-sized buffer during the mandatory handshake.
        if (payload_len > 1024 * 1024) return error.InputPolicyFrameTooLarge;

        switch (header.tag) {
            .Ack => {
                if (payload_len != 0) return error.InvalidInputPolicyAck;
                // Reads above are exact-size, so bytes belonging to a frame
                // after Ack remain in the socket for the caller's normal
                // SocketBuffer. No partial frame can be stranded here.
                return read_buf;
            },
            .InputPolicyMismatch => {
                var discard: [1024]u8 = undefined;
                var remaining = payload_len;
                while (remaining > 0) {
                    const amount = @min(remaining, discard.len);
                    try readPolicyBytes(fd, discard[0..amount]);
                    remaining -= amount;
                }
                return error.InputPolicyMismatch;
            },
            else => {
                try read_buf.buf.appendSlice(alloc, std.mem.asBytes(&header));
                const old_len = read_buf.buf.items.len;
                try read_buf.buf.resize(alloc, old_len + payload_len);
                try readPolicyBytes(fd, read_buf.buf.items[old_len..]);
            },
        }
    }
}

fn readPolicyBytes(fd: i32, dest: []u8) !void {
    var offset: usize = 0;
    while (offset < dest.len) {
        var poll_fds = [_]lib_posix.pollfd{.{ .fd = fd, .events = lib_posix.POLL.IN, .revents = 0 }};
        const poll_result = try lib_posix.poll(&poll_fds, 1000);
        if (poll_result == 0) return error.InputPolicyTimeout;
        if (poll_fds[0].revents & lib_posix.POLL.IN == 0 and
            poll_fds[0].revents & (lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL) != 0)
        {
            return error.ConnectionClosed;
        }
        const n = try lib_posix.read(fd, dest[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

const SessionProbeError = error{
    Timeout,
    ConnectionRefused,
    Unexpected,
    InfoSizeMismatch,
};

const SessionProbeResult = struct {
    fd: i32,
    info: Info,
    labels: ?[]const u8,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *const SessionProbeResult) void {
        if (self.labels) |lbl| self.alloc.free(lbl);
        lib_posix.close(self.fd);
    }
};

pub fn probeSession(
    alloc: std.mem.Allocator,
    socket_path: []const u8,
) SessionProbeError!SessionProbeResult {
    const timeout_ms = 1000;
    const fd = try connectSession(socket_path);
    errdefer lib_posix.close(fd);

    send(fd, .Info, "") catch return error.Unexpected;
    send(fd, .LabelGet, "") catch {};

    var poll_fds = [_]lib_posix.pollfd{.{ .fd = fd, .events = lib_posix.POLL.IN, .revents = 0 }};
    const poll_result = lib_posix.poll(&poll_fds, timeout_ms) catch return error.Unexpected;
    if (poll_result == 0) {
        return error.Timeout;
    }

    var sb = SocketBuffer.initFromDaemon(alloc) catch return error.Unexpected;
    defer sb.deinit();

    const n = sb.read(fd) catch return error.Unexpected;
    if (n == 0) return error.Unexpected;

    var info_result: ?Info = null;
    var labels: ?[]const u8 = null;
    errdefer if (labels) |lbl| alloc.free(lbl);

    while (true) {
        if (sb.next()) |msg| {
            if (msg.header.tag == .Info) {
                if (msg.payload.len != @sizeOf(Info)) return error.InfoSizeMismatch;
                info_result = std.mem.bytesToValue(Info, msg.payload[0..@sizeOf(Info)]);
            }
            if (msg.header.tag == .LabelData) {
                labels = alloc.dupe(u8, msg.payload) catch null;
            }

            if (info_result != null and labels != null) break;
            continue;
        }

        // No complete message available, wait for more data
        const more = lib_posix.poll(&poll_fds, 50) catch break;
        if (more == 0) break;
        const n_read = sb.read(fd) catch break;
        if (n_read == 0) break;
    }

    if (info_result) |info| {
        return .{
            .fd = fd,
            .info = info,
            .labels = labels,
            .alloc = alloc,
        };
    }
    return error.Unexpected;
}

//  WIRE PROTOCOL FREEZE: read before "fixing" any test below.
//
//  Changing these constants does not fix the test; it violates the
//  same-build wire contract between clients and session daemons.
//
//  Need a new field?   → add a new `Tag` value (next free integer).
//  Need to remove one? → don't. Reserve the integer, stop sending it.
test "Info wire size is frozen" {
    try std.testing.expectEqual(@as(usize, 552), @sizeOf(Info));
    // packed struct{u8,u32} backs to u40 → @sizeOf rounds to 8, not 5.
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(Header));
}

test "Tag wire values are frozen" {
    inline for (.{
        .{ Tag.Input, 0 },            .{ Tag.Output, 1 },        .{ Tag.Resize, 2 },
        .{ Tag.Detach, 3 },           .{ Tag.DetachAll, 4 },     .{ Tag.Kill, 5 },
        .{ Tag.Info, 6 },             .{ Tag.Init, 7 },          .{ Tag.History, 8 },
        .{ Tag.Run, 9 },              .{ Tag.Ack, 10 },          .{ Tag.Switch, 11 },
        .{ Tag.Write, 12 },           .{ Tag.TaskComplete, 13 }, .{ Tag.LabelGet, 14 },
        .{ Tag.LabelSet, 15 },        .{ Tag.LabelClear, 16 },   .{ Tag.LabelData, 17 },
        .{ Tag.Send, 18 },            .{ Tag.InputPolicy, 19 },  .{ Tag.InputPolicyMismatch, 20 },
        .{ Tag.RequestRejected, 21 },
    }) |p| try std.testing.expectEqual(@as(u8, p[1]), @intFromEnum(p[0]));
}

test "input logging policy defaults are explicit booleans" {
    try std.testing.expectEqual(@as(?bool, false), InputPolicy.init(false).value());
    try std.testing.expectEqual(@as(?bool, true), InputPolicy.init(true).value());
    try std.testing.expectEqual(@as(?bool, null), (InputPolicy{ .log_input = 2 }).value());
}

test "policy acknowledgement preserves preceding frames without consuming following bytes" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), test_c.socketpair(test_c.AF_UNIX, test_c.SOCK_STREAM, 0, &fds));
    defer _ = test_c.close(fds[0]);
    defer _ = test_c.close(fds[1]);

    try send(fds[1], .Output, "startup");
    try send(fds[1], .Ack, "");
    const following = Header{ .tag = .Output, .len = 3 };
    const following_bytes = std.mem.asBytes(&following);
    try writeAll(fds[1], following_bytes[0..2]);

    var pending = try acknowledgeInputPolicy(std.testing.allocator, fds[0], false);
    defer pending.deinit();
    const output = pending.next().?;
    try std.testing.expectEqual(Tag.Output, output.header.tag);
    try std.testing.expectEqualStrings("startup", output.payload);
    try std.testing.expect(pending.next() == null);

    var unread: [2]u8 = undefined;
    try readPolicyBytes(fds[0], &unread);
    try std.testing.expectEqualSlices(u8, following_bytes[0..2], &unread);
}

test "socket buffer rejects an oversized declared frame before payload allocation" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), test_c.socketpair(test_c.AF_UNIX, test_c.SOCK_STREAM, 0, &fds));
    defer _ = test_c.close(fds[0]);
    defer _ = test_c.close(fds[1]);

    const oversized = Header{
        .tag = .Input,
        .len = @intCast(maxPayloadLen(.Input) + 1),
    };
    try writeAll(fds[1], std.mem.asBytes(&oversized));

    var buffer = try SocketBuffer.init(std.testing.allocator);
    defer buffer.deinit();
    try std.testing.expectError(error.FrameTooLarge, buffer.read(fds[0]));
}

test "socket buffer applies direction-aware Output limits" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), test_c.socketpair(test_c.AF_UNIX, test_c.SOCK_STREAM, 0, &fds));
    defer _ = test_c.close(fds[0]);
    defer _ = test_c.close(fds[1]);

    const large_output = Header{
        .tag = .Output,
        .len = @intCast(maxClientPayloadLen(.Output) + 1),
    };
    try writeAll(fds[1], std.mem.asBytes(&large_output));

    var daemon_ingress = try SocketBuffer.init(std.testing.allocator);
    defer daemon_ingress.deinit();
    try std.testing.expectError(error.FrameTooLarge, daemon_ingress.read(fds[0]));

    var response_buf = try SocketBuffer.initFromDaemon(std.testing.allocator);
    defer response_buf.deinit();
    try response_buf.buf.appendSlice(std.testing.allocator, std.mem.asBytes(&large_output));
    try response_buf.validatePendingHeader();
}

test "switch target carries policy and rejects malformed payloads" {
    const off = try parseSwitchTarget("\x00dev");
    try std.testing.expect(!off.log_input);
    try std.testing.expectEqualStrings("dev", off.name);

    const on = try parseSwitchTarget("\x01nested.dev");
    try std.testing.expect(on.log_input);
    try std.testing.expectEqualStrings("nested.dev", on.name);

    try std.testing.expectError(error.InvalidSwitchTarget, parseSwitchTarget(""));
    try std.testing.expectError(error.InvalidSwitchTarget, parseSwitchTarget("\x00"));
    try std.testing.expectError(error.InvalidSwitchTarget, parseSwitchTarget("\x02dev"));
}

pub fn roundTripForTag(
    alloc: std.mem.Allocator,
    socket_path: []const u8,
    request_tag: Tag,
    payload: []const u8,
    expected_tag: Tag,
) SessionProbeError![]u8 {
    const timeout_ms = 1000;
    const fd = try connectSession(socket_path);
    defer lib_posix.close(fd);

    send(fd, request_tag, payload) catch return error.Unexpected;

    var poll_fds = [_]lib_posix.pollfd{.{ .fd = fd, .events = lib_posix.POLL.IN, .revents = 0 }};
    const poll_result = lib_posix.poll(&poll_fds, timeout_ms) catch return error.Unexpected;
    if (poll_result == 0) return error.Timeout;

    var sb = SocketBuffer.initFromDaemon(alloc) catch return error.Unexpected;
    defer sb.deinit();

    const n = sb.read(fd) catch return error.Unexpected;
    if (n == 0) return error.Unexpected;

    while (sb.next()) |msg| {
        if (msg.header.tag == expected_tag) {
            return alloc.dupe(u8, msg.payload) catch return error.Unexpected;
        }
    }
    return error.Unexpected;
}

test "zeroed Info has no stack garbage in wire bytes" {
    var info = std.mem.zeroes(Info);
    info.clients_len = 3;
    info.pid = 999;
    info.task_exit_code = 7;
    const bytes = std.mem.asBytes(&info);
    // Tail padding after task_exit_code must be zero (asBytes ships it).
    const last_field_end = @offsetOf(Info, "task_exit_code") + @sizeOf(u8);
    for (bytes[last_field_end..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
