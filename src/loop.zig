const std = @import("std");
const ghostty_vt = @import("ghostty-vt");
const ipc = @import("ipc.zig");
const input = @import("input.zig");
const log = @import("log.zig");
const util = @import("util.zig");
const cross = @import("cross.zig");
const socket = @import("socket.zig");
const label = @import("label.zig");
const lib_posix = @import("posix.zig");
const Cfg = @import("cfg.zig");
const signal = @import("signal.zig");
const assert = std.debug.assert;
const daemonize = @import("daemonize.zig");
const builtin = @import("builtin");

const WRITE_MARKER_PREFIX = "\x1bPzmxw:";
const WRITE_MARKER_SUFFIX = "\x1b\\";

fn appendShellWriteMarker(
    gpa: std.mem.Allocator,
    command: *std.ArrayList(u8),
    token: []const u8,
    kind: u8,
) !void {
    try command.appendSlice(gpa, "printf '\\033Pzmxw:");
    try command.appendSlice(gpa, token);
    try command.appendSlice(gpa, ":");
    try command.append(gpa, kind);
    try command.appendSlice(gpa, "\\033\\\\'");
}

fn appendReceiptedWriteLine(
    gpa: std.mem.Allocator,
    command: *std.ArrayList(u8),
    token: []const u8,
) !void {
    try command.appendSlice(gpa, "; ");
    try appendShellWriteMarker(gpa, command, token, 'N');
    try command.append(gpa, '\r');
}

/// clientLoop sends ipc commands to its corresponding daemon.  It uses poll() as its non-blocking
/// mechanism. It will send stdin to the daemon and receive stdout from the daemon.
pub fn clientLoop(
    io: std.Io,
    gpa: std.mem.Allocator,
    client_sock_fd: i32,
    socket_dir: []const u8,
    log_input: bool,
) !ClientResult {
    std.log.info("client loop fd={d}", .{client_sock_fd});
    defer lib_posix.close(client_sock_fd);

    // Input-capable peers must acknowledge the daemon's immutable policy
    // before any terminal initialization or keyboard bytes are sent.
    var read_buf = try ipc.acknowledgeInputPolicy(gpa, client_sock_fd, log_input);
    defer read_buf.deinit();

    try signal.openSignalPipe();
    signal.installWakeHandler(@intFromEnum(lib_posix.SIG.WINCH));

    // Make socket non-blocking to avoid blocking on writes
    var sock_flags = try lib_posix.fcntl(client_sock_fd, lib_posix.F.GETFL, 0);
    sock_flags |= lib_posix.O_NONBLOCK;
    _ = try lib_posix.fcntl(client_sock_fd, lib_posix.F.SETFL, sock_flags);

    // Buffer for outgoing socket writes
    var sock_write_buf = try std.ArrayList(u8).initCapacity(gpa, 4096);
    defer sock_write_buf.deinit(gpa);

    // Send init message with terminal size (buffered)
    const size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
    try ipc.appendMessage(gpa, &sock_write_buf, .Init, std.mem.asBytes(&size));

    var poll_fds = try std.ArrayList(lib_posix.pollfd).initCapacity(gpa, 4);
    defer poll_fds.deinit(gpa);

    var stdout_buf = try std.ArrayList(u8).initCapacity(gpa, 4096);
    defer stdout_buf.deinit(gpa);

    // The daemon can emit output while the policy acknowledgement is in
    // flight. acknowledgeInputPolicy removes only its Ack frame and leaves
    // all other complete or partial frames in read_buf.
    while (read_buf.next()) |msg| {
        if (msg.header.tag == .Output and msg.payload.len > 0) {
            try stdout_buf.appendSlice(gpa, msg.payload);
        }
    }

    var detach_classifier = input.StreamClassifier{};
    var detach_pending = std.ArrayList(u8).empty;
    defer detach_pending.deinit(gpa);
    var detach_deadline: ?std.Io.Timestamp = null;

    const stdin_fd = lib_posix.STDIN_FILENO;

    // Make stdin non-blocking. O_NONBLOCK is set on the open file description,
    // which is shared with the parent shell; restore on exit to avoid
    // corrupting the parent's stdin.
    const stdin_orig_flags = try lib_posix.fcntl(stdin_fd, lib_posix.F.GETFL, 0);
    _ = try lib_posix.fcntl(stdin_fd, lib_posix.F.SETFL, stdin_orig_flags | lib_posix.O_NONBLOCK);
    defer _ = lib_posix.fcntl(stdin_fd, lib_posix.F.SETFL, stdin_orig_flags) catch {};

    while (true) {
        poll_fds.clearRetainingCapacity();

        try poll_fds.append(gpa, .{
            .fd = stdin_fd,
            .events = lib_posix.POLL.IN,
            .revents = 0,
        });

        // Poll socket for read, and also for write if we have pending data
        var sock_events: i16 = lib_posix.POLL.IN;
        if (sock_write_buf.items.len > 0) {
            sock_events |= lib_posix.POLL.OUT;
        }
        try poll_fds.append(gpa, .{
            .fd = client_sock_fd,
            .events = sock_events,
            .revents = 0,
        });

        try poll_fds.append(gpa, .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 });

        if (stdout_buf.items.len > 0) {
            try poll_fds.append(gpa, .{
                .fd = lib_posix.STDOUT_FILENO,
                .events = lib_posix.POLL.OUT,
                .revents = 0,
            });
        }

        const poll_timeout: i32 = if (detach_deadline) |deadline| blk: {
            const remaining_ns = deadline.nanoseconds - std.Io.Timestamp.now(io, .awake).nanoseconds;
            if (remaining_ns <= 0) break :blk 0;
            break :blk @intCast(@max(1, @divTrunc(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
        } else -1;
        const poll_result = try lib_posix.poll(poll_fds.items, poll_timeout);
        if (poll_result == 0 and detach_pending.items.len > 0) {
            // A lone Escape key is also the prefix of every encoded detach
            // form. Give a split sequence a short assembly window, then pass
            // Escape through so interactive applications remain responsive.
            try ipc.appendMessage(gpa, &sock_write_buf, .Input, detach_pending.items);
            detach_pending.clearRetainingCapacity();
            detach_classifier.finish();
            detach_deadline = null;
            continue;
        }

        if (poll_fds.items[2].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            const next_size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
            try ipc.appendMessage(gpa, &sock_write_buf, .Resize, std.mem.asBytes(&next_size));
        }

        // Handle socket read (incoming Output messages from daemon)
        if (poll_fds.items[1].revents & lib_posix.POLL.IN != 0) {
            const n = read_buf.read(client_sock_fd) catch |err| {
                if (err == error.WouldBlock) continue;
                if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) {
                    return ClientResult{ .kind = .detach, .session_name = null };
                }
                std.log.err("daemon read err={s}", .{@errorName(err)});
                return err;
            };
            if (n == 0) {
                std.log.info("server closed connection", .{});
                // Server closed connection
                return ClientResult{ .kind = .detach, .session_name = null };
            }

            while (read_buf.next()) |msg| {
                switch (msg.header.tag) {
                    .Output => {
                        if (msg.payload.len > 0) {
                            try stdout_buf.appendSlice(gpa, msg.payload);
                        }
                    },
                    .Resize => {
                        // daemon is asking for the client's window size usually in response
                        // to this client being set as leader.
                        const next_size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
                        try ipc.appendMessage(
                            gpa,
                            &sock_write_buf,
                            .Resize,
                            std.mem.asBytes(&next_size),
                        );
                    },
                    .Switch => {
                        std.log.info("switch session", .{});
                        const target = try ipc.parseSwitchTarget(msg.payload);
                        try socket.validateCanonicalSessionName(socket_dir, target.name);
                        // Transition barrier: nothing already buffered for the old
                        // connection may be carried into the next one, and unread
                        // terminal typeahead must not become input to the target.
                        sock_write_buf.clearRetainingCapacity();
                        _ = cross.c.tcflush(lib_posix.STDIN_FILENO, cross.c.TCIFLUSH);
                        return ClientResult{
                            .kind = .switch_session,
                            .session_name = try gpa.dupe(u8, target.name),
                            .log_input = target.log_input,
                        };
                    },
                    else => {},
                }
            }
        }

        // Socket control is processed before stdin. In particular, a Switch
        // observed in this poll cycle returns above before any concurrently
        // readable terminal typeahead can be consumed.
        const inp_flags = (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL);
        if (poll_fds.items[0].revents & inp_flags != 0) {
            var buf: [4096]u8 = undefined;
            const n_opt: ?usize = lib_posix.read(stdin_fd, &buf) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };

            if (n_opt) |n| {
                if (n > 0) {
                    // Hold an unfinished escape sequence until it can be
                    // distinguished from an encoded Ctrl+\\ detach key. This
                    // prevents a split detach prefix from reaching the PTY.
                    try detach_pending.appendSlice(gpa, buf[0..n]);
                    const detach_result: input.StreamClassifier.FeedResult = if (input.isCtrlBackslash(buf[0..n]))
                        .ctrl_backslash
                    else
                        detach_classifier.feedResult(buf[0..n]);
                    switch (detach_result) {
                        .pending => {},
                        .ctrl_backslash => {
                            std.log.info("detach key detected", .{});
                            detach_pending.clearRetainingCapacity();
                            detach_classifier.finish();
                            detach_deadline = null;
                            try ipc.appendMessage(gpa, &sock_write_buf, .Detach, "");
                        },
                        .user_input, .ignored => {
                            try ipc.appendMessage(gpa, &sock_write_buf, .Input, detach_pending.items);
                            detach_pending.clearRetainingCapacity();
                            detach_deadline = null;
                        },
                    }
                    if (detach_classifier.hasPending() and detach_deadline == null) {
                        const now = std.Io.Timestamp.now(io, .awake);
                        detach_deadline = .{ .nanoseconds = now.nanoseconds + 50 * std.time.ns_per_ms };
                    }
                } else {
                    std.log.info("eof stdin", .{});
                    return ClientResult{ .kind = .detach, .session_name = null };
                }
            }
        }

        // Handle socket write (flush buffered messages to daemon)
        if (poll_fds.items[1].revents & lib_posix.POLL.OUT != 0) {
            if (sock_write_buf.items.len > 0) {
                const n = lib_posix.write(client_sock_fd, sock_write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) {
                        std.log.info("connection reset or broken pipe", .{});
                        return ClientResult{ .kind = .detach, .session_name = null };
                    }
                    return err;
                };
                if (n > 0) {
                    try sock_write_buf.replaceRange(gpa, 0, n, &[_]u8{});
                }
            }
        }

        if (stdout_buf.items.len > 0) {
            const n = lib_posix.write(lib_posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                if (err == error.WouldBlock) break :blk 0;
                return err;
            };
            if (n > 0) {
                try stdout_buf.replaceRange(gpa, 0, n, &[_]u8{});
            }
        }

        if (poll_fds.items[1].revents & (lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL) != 0) {
            std.log.info("poll hup|err|nval", .{});
            return ClientResult{ .kind = .detach, .session_name = null };
        }
    }
}

const ClientAction = enum { keep, detach, detach_all, kill };

fn dispatchClientMessage(
    daemon: *Daemon,
    gpa: std.mem.Allocator,
    client: *Client,
    pty_fd: i32,
    term: *ghostty_vt.Terminal,
    vt_stream: anytype,
    msg: ipc.SocketMsg,
) !ClientAction {
    switch (msg.header.tag) {
        .Input => try daemon.handleInput(gpa, client, msg.payload),
        .Send => try daemon.handleSend(gpa, client, msg.payload),
        .Output => try daemon.handleOutput(gpa, msg.payload, vt_stream),
        .Init => try daemon.handleInit(gpa, client, pty_fd, term, msg.payload),
        .InputPolicy => try daemon.handleInputPolicy(gpa, client, msg.payload),
        .Switch => try daemon.handleSwitch(gpa, msg.payload),
        .Resize => try daemon.handleResize(gpa, client, pty_fd, term, msg.payload),
        .Detach => return .detach,
        .DetachAll => return .detach_all,
        .Kill => return .kill,
        .Info => try daemon.handleInfo(gpa, client),
        .LabelGet => try daemon.handleLabelGet(gpa, client),
        .LabelSet => try daemon.handleLabelSet(gpa, client, msg.payload),
        .LabelClear => try daemon.handleLabelClear(gpa, client),
        .History => try daemon.handleHistory(gpa, client, term, msg.payload),
        .Run => try daemon.handleRun(gpa, client, msg.payload),
        .Ack, .TaskComplete, .LabelData, .InputPolicyMismatch, .RequestRejected => {},
        .Write => try daemon.handleWrite(gpa, client, msg.payload),
        _ => std.log.warn("ignoring unknown IPC tag={d}", .{@intFromEnum(msg.header.tag)}),
    }
    return .keep;
}

/// dameonLoop is what the daemon runs to send and receive ipc commands from its corresponding
/// clients.  It uses poll() as its non-blocking mechanism.
fn daemonLoop(daemon: *Daemon, gpa: std.mem.Allocator, io: std.Io, server_sock_fd: lib_posix.socket_t, pty_fd: i32) !void {
    std.log.info("daemon started session={s} pty_fd={d}", .{ daemon.session_name, pty_fd });
    if (daemon.log_input) {
        std.log.warn("SECURITY WARNING: PTY input logging is enabled for session={s}", .{daemon.session_name});
    }

    try signal.openSignalPipe();
    signal.installWakeHandler(@intFromEnum(lib_posix.SIG.TERM));
    var poll_fds = try std.ArrayList(lib_posix.pollfd).initCapacity(gpa, 8);
    defer poll_fds.deinit(gpa);

    const init_size = ipc.getTerminalSize(pty_fd);
    var term = try ghostty_vt.Terminal.init(io, gpa, .{
        .cols = init_size.cols,
        .rows = init_size.rows,
        .max_scrollback = daemon.cfg.max_scrollback,
    });
    defer term.deinit(gpa);
    var vt_stream = term.vtStream();
    defer vt_stream.deinit();

    // Carries the tail of the previous PTY read so the task-exit marker
    // search below can see across a read() boundary. Sized to comfortably
    // hold "ZMX_TASK_COMPLETED:" (19 bytes) plus a u8 exit code and CRLF.
    var marker_carry: [32]u8 = undefined;
    var marker_carry_len: usize = 0;

    daemon_loop: while (daemon.running) {
        poll_fds.clearRetainingCapacity();

        try poll_fds.append(gpa, .{
            .fd = server_sock_fd,
            .events = lib_posix.POLL.IN,
            .revents = 0,
        });

        var pty_events: i16 = lib_posix.POLL.IN;
        const pty_write_ready = !daemon.pty_write_waiting_for_marker;
        if (daemon.pty_write_buf.items.len > 0 and pty_write_ready) {
            pty_events |= lib_posix.POLL.OUT;
        }
        try poll_fds.append(gpa, .{
            .fd = pty_fd,
            .events = pty_events,
            .revents = 0,
        });

        try poll_fds.append(gpa, .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 });

        for (daemon.clients.items) |client| {
            var events: i16 = lib_posix.POLL.IN;
            if (client.has_pending_output) {
                events |= lib_posix.POLL.OUT;
            }
            try poll_fds.append(gpa, .{
                .fd = client.socket_fd,
                .events = events,
                .revents = 0,
            });
        }

        _ = try lib_posix.poll(poll_fds.items, daemon.inputPollTimeout(io));
        try daemon.expireWriteTransaction(gpa, io);
        try daemon.flushExpiredPendingInput(gpa, io);

        if (poll_fds.items[2].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            std.log.info(
                "SIGTERM received, shutting down gracefully session={s}",
                .{daemon.session_name},
            );
            break :daemon_loop;
        }

        if (poll_fds.items[0].revents & (lib_posix.POLL.ERR | lib_posix.POLL.HUP | lib_posix.POLL.NVAL) != 0) {
            std.log.err("server socket error revents={d}", .{poll_fds.items[0].revents});
            break :daemon_loop;
        } else if (poll_fds.items[0].revents & lib_posix.POLL.IN != 0) {
            const client_fd = try lib_posix.accept(
                server_sock_fd,
                null,
                null,
                lib_posix.SOCK.NONBLOCK | lib_posix.SOCK.CLOEXEC,
            );
            const client = try gpa.create(Client);
            client.* = Client{
                .alloc = gpa,
                .socket_fd = client_fd,
                .read_buf = try ipc.SocketBuffer.init(gpa),
                .write_buf = undefined,
            };
            // 64KB initial capacity lets ~15 broadcast cycles (N_TTY_BUF_SIZE reads
            // * header) accumulate before the first ArrayList growth. The write
            // buffer is userspace-only: it drains via POLLOUT to the client socket,
            // which has no corresponding kernel-imposed per-write limit.
            client.write_buf = try std.ArrayList(u8).initCapacity(client.alloc, 65536);
            try daemon.clients.append(gpa, client);
            std.log.info(
                "client connected fd={d} total={d}",
                .{ client_fd, daemon.clients.items.len },
            );
        }

        const inp_flags = lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL;
        if (poll_fds.items[1].revents & inp_flags != 0) {
            // Read from PTY. Buffer is sized to N_TTY_BUF_SIZE (4096): the hard
            // kernel limit for the N_TTY line discipline. A larger buffer doesn't
            // help: each read() from a PTY master returns at most 4096 bytes
            // regardless of the userspace buffer size.
            var buf: [4096]u8 = undefined;
            const n_opt: ?usize = lib_posix.read(pty_fd, &buf) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                break :blk 0;
            };

            if (n_opt) |n| {
                if (n == 0) {
                    // EOF: Shell exited
                    std.log.info("shell exited pty_fd={d}", .{pty_fd});
                    // Let the rest of this poll iteration complete so client
                    // write buffers are flushed via the normal POLLOUT path.
                    // On the next iteration, daemon.running will be false.
                    daemon.running = false;
                } else {
                    try daemon.observeWriteMarker(gpa, buf[0..n]);
                    // Feed PTY output to terminal emulator for state tracking
                    vt_stream.nextSlice(buf[0..n]);
                    daemon.has_pty_output = true;

                    // When no real terminal client has attached yet, respond to
                    // terminal queries (e.g. DA1/DA2) on behalf of the terminal.
                    // This prevents fish from waiting 10s for unanswered queries.
                    // `has_terminal_client` is only set when a client sends .Init
                    // (a real zmx attach), not when a `zmx run` tail-only client
                    // connects.
                    if (!daemon.has_terminal_client and
                        daemon.pty_write_buf.items.len < Daemon.PTY_WRITE_BUF_MAX)
                    {
                        var response = std.ArrayList(u8).empty;
                        defer response.deinit(gpa);
                        util.respondToDeviceAttributes(gpa, &response, buf[0..n]);
                        _ = daemon.queuePtyInput(gpa, response.items);
                    }

                    // In run mode, scan output for exit code marker. The marker
                    // can straddle two PTY reads (more likely under a throttled
                    // scheduler, e.g. containers), so prepend the tail carried
                    // over from the previous read before searching.
                    if (daemon.is_task_mode and daemon.task_exit_code == null) {
                        var scan_buf: [marker_carry.len + buf.len]u8 = undefined;
                        @memcpy(scan_buf[0..marker_carry_len], marker_carry[0..marker_carry_len]);
                        @memcpy(scan_buf[marker_carry_len..][0..n], buf[0..n]);
                        const scan_len = marker_carry_len + n;

                        if (util.findTaskExitMarker(scan_buf[0..scan_len])) |exit_code| {
                            daemon.task_exit_code = exit_code;
                            daemon.task_ended_at = @intCast(std.Io.Timestamp.now(io, .real).toSeconds());

                            std.log.info("task completed exit_code={d}", .{exit_code});

                            // Notify connected clients
                            for (daemon.clients.items) |c| {
                                c.appendMessage(gpa, .TaskComplete, &[_]u8{exit_code}) catch {};
                            }
                        }

                        marker_carry_len = @min(marker_carry.len, scan_len);
                        @memcpy(
                            marker_carry[0..marker_carry_len],
                            scan_buf[scan_len - marker_carry_len .. scan_len],
                        );
                    }

                    // Broadcast data to all clients.
                    // Rewrite OSC 133;A to include redraw=0 so the outer terminal
                    // does not clear prompt lines on resize (issue #111).
                    const broadcast_data = util.rewritePromptRedraw(gpa, buf[0..n]) orelse buf[0..n];
                    defer if (broadcast_data.ptr != buf[0..n].ptr) gpa.free(broadcast_data);
                    for (daemon.clients.items) |client| {
                        client.appendMessage(gpa, .Output, broadcast_data) catch |err| {
                            std.log.warn(
                                "failed to buffer output for client err={s}",
                                .{@errorName(err)},
                            );
                            continue;
                        };
                    }
                }
            }
        }

        if (poll_fds.items[1].revents & lib_posix.POLL.OUT != 0) {
            while (daemon.pty_write_buf.items.len > 0) {
                const transaction_len = @min(
                    daemon.pty_write_transaction_remaining,
                    daemon.pty_write_buf.items.len,
                );
                const write_len = if (transaction_len > 0)
                    (std.mem.indexOfScalar(u8, daemon.pty_write_buf.items[0..transaction_len], '\r') orelse
                        (transaction_len - 1)) + 1
                else
                    daemon.pty_write_buf.items.len;
                const n = lib_posix.write(pty_fd, daemon.pty_write_buf.items[0..write_len]) catch |err| {
                    if (err != error.WouldBlock) {
                        std.log.warn("pty write failed: {s}", .{@errorName(err)});
                        daemon.pty_write_buf.clearRetainingCapacity();
                        try daemon.finishWriteTransaction(gpa, false);
                    }
                    break;
                };
                if (n == 0) break;
                const transaction_written = @min(n, daemon.pty_write_transaction_remaining);
                daemon.pty_write_transaction_remaining -= transaction_written;
                daemon.pty_write_buf.replaceRange(gpa, 0, n, &[_]u8{}) catch unreachable;
                if (transaction_written > 0 and n == write_len) {
                    // The generated line ends with a randomized shell receipt.
                    // Do not deliver its successor until that receipt comes
                    // back through PTY output, proving the shell consumed it.
                    daemon.pty_write_waiting_for_marker = true;
                    break;
                }
            }
        }

        var i: usize = daemon.clients.items.len;
        // Only iterate over clients that were present when poll_fds was constructed
        // poll_fds contains [server, pty, sig_pipe, client0, client1, ...]
        // So number of clients in poll_fds is poll_fds.items.len - 3
        const num_polled_clients = poll_fds.items.len - 3;
        if (i > num_polled_clients) {
            // If we have more clients than polled (i.e. we just accepted one), start from the
            // polled ones
            i = num_polled_clients;
        }

        clients_loop: while (i > 0) {
            i -= 1;
            const client = daemon.clients.items[i];
            const revents = poll_fds.items[i + 3].revents;

            if (client.close_requested) {
                const last = daemon.closeClient(gpa, client, i, false);
                if (last) break :daemon_loop;
                continue;
            }

            if (revents & lib_posix.POLL.IN != 0) {
                const n = client.read_buf.read(client.socket_fd) catch |err| {
                    if (err == error.WouldBlock) continue;
                    std.log.debug(
                        "client read err={s} fd={d}",
                        .{ @errorName(err), client.socket_fd },
                    );
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                };

                if (n == 0) {
                    // Client closed connection
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                }

                while (client.read_buf.next()) |msg| {
                    const action = dispatchClientMessage(
                        daemon,
                        gpa,
                        client,
                        pty_fd,
                        &term,
                        &vt_stream,
                        msg,
                    ) catch |err| {
                        std.log.warn("closing client after request failure err={s}", .{@errorName(err)});
                        const last = daemon.closeClient(gpa, client, i, false);
                        if (last) break :daemon_loop;
                        continue :clients_loop;
                    };
                    switch (action) {
                        .detach => {
                            daemon.handleDetach(gpa, client, i);
                            break :clients_loop;
                        },
                        .detach_all => {
                            daemon.handleDetachAll(gpa);
                            break :clients_loop;
                        },
                        .kill => {
                            break :daemon_loop;
                        },
                        .keep => {},
                    }
                }
            }

            if (revents & lib_posix.POLL.OUT != 0) {
                // Flush pending output buffers
                const n = lib_posix.write(client.socket_fd, client.write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    // Error on write, close client
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                };

                if (n > 0) {
                    client.consumeWritten(n);
                    client.write_buf.replaceRange(gpa, 0, n, &[_]u8{}) catch unreachable;
                }

                if (client.write_buf.items.len == 0) {
                    client.has_pending_output = false;
                }
            }

            if (revents & (lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL) != 0) {
                const last = daemon.closeClient(gpa, client, i, false);
                if (last) break :daemon_loop;
            }
        }
    }
}

pub const ClientResult = struct {
    kind: enum {
        detach,
        switch_session,
    },
    session_name: ?[]const u8,
    log_input: bool = false,
};

/// Client represents each terminal that has connected to a session.
///
/// Multiple Clients can connect to a single session.
pub const Client = struct {
    const BACKLOG_MAX = 4 * 1024 * 1024;
    const MAX_SINGLE_FRAME = 64 * 1024 * 1024 + @sizeOf(ipc.Header);

    alloc: std.mem.Allocator,
    socket_fd: i32,
    has_pending_output: bool = false,
    read_buf: ipc.SocketBuffer,
    write_buf: std.ArrayList(u8),
    input_policy_ack: ?bool = null,
    input_classifier: input.StreamClassifier = .{},
    pending_input: std.ArrayList(u8) = .empty,
    pending_input_deadline: ?std.Io.Timestamp = null,
    close_requested: bool = false,
    large_frame_offset: ?usize = null,
    large_frame_remaining: usize = 0,

    pub fn appendMessage(self: *Client, gpa: std.mem.Allocator, tag: ipc.Tag, data: []const u8) !void {
        const frame_len = @sizeOf(ipc.Header) + data.len;
        if (data.len > ipc.maxPayloadLen(tag) or !messageFits(self.ordinaryBacklogLen(), frame_len)) {
            self.close_requested = true;
            std.log.warn("closing slow client with full output queue", .{});
            return;
        }
        try ipc.appendMessage(gpa, &self.write_buf, tag, data);
        self.has_pending_output = true;
    }

    /// History and terminal restoration are the only daemon responses allowed
    /// to use the 64 MiB wire limit. At most one such frame may coexist with
    /// the independently bounded ordinary-output backlog.
    pub fn appendLargeMessage(self: *Client, gpa: std.mem.Allocator, tag: ipc.Tag, data: []const u8) !void {
        const frame_len = @sizeOf(ipc.Header) + data.len;
        if ((tag != .History and tag != .Output) or
            data.len > ipc.maxPayloadLen(tag) or
            frame_len > MAX_SINGLE_FRAME or
            self.large_frame_remaining != 0 or
            self.ordinaryBacklogLen() > BACKLOG_MAX)
        {
            self.close_requested = true;
            std.log.warn("closing slow client with full large-response queue", .{});
            return;
        }

        const offset = self.write_buf.items.len;
        try ipc.appendMessage(gpa, &self.write_buf, tag, data);
        self.large_frame_offset = offset;
        self.large_frame_remaining = frame_len;
        self.has_pending_output = true;
    }

    fn ordinaryBacklogLen(self: *const Client) usize {
        return self.write_buf.items.len - self.large_frame_remaining;
    }

    fn messageFits(ordinary_len: usize, frame_len: usize) bool {
        return frame_len <= BACKLOG_MAX and ordinary_len <= BACKLOG_MAX - frame_len;
    }

    fn consumeWritten(self: *Client, n: usize) void {
        const offset = self.large_frame_offset orelse return;
        if (n <= offset) {
            self.large_frame_offset = offset - n;
            return;
        }

        const consumed = @min(n - offset, self.large_frame_remaining);
        self.large_frame_remaining -= consumed;
        if (self.large_frame_remaining == 0) {
            self.large_frame_offset = null;
        } else {
            self.large_frame_offset = 0;
        }
    }

    pub fn deinit(self: *Client) void {
        lib_posix.close(self.socket_fd);
        self.read_buf.deinit();
        self.write_buf.deinit(self.alloc);
        self.pending_input.deinit(self.alloc);
    }
};

/// Daemon is responsible for managing a zmx session.
///
/// It holds all the state for a running session.  Instead of a single daemon for all sessions, we
/// create a daemon for every session.  This has some benefits. The ipc communication between
/// session clients and the daemon doesn't need to be tagged with the session name.  If a daemon
/// crashes for one session won't crash all the other sessions.
///
/// Conceptually it's also much simpler to reason about.
pub const Daemon = struct {
    io: std.Io = undefined,
    cfg: *Cfg,
    session_name: []const u8,
    socket_path: []const u8,
    // === opt ===
    pty_write_buf: std.ArrayList(u8) = .empty,
    /// A `write` transaction is accepted into this queue atomically, then each
    /// canonical shell line waits for a randomized receipt from PTY output.
    /// The requesting client receives Ack only after a final size-verified
    /// completion receipt.
    pty_write_transaction_remaining: usize = 0,
    pty_write_waiting_for_marker: bool = false,
    pty_write_client_fd: ?i32 = null,
    pty_write_deadline: ?std.Io.Timestamp = null,
    pty_write_token: [32]u8 = @splat(0),
    pty_write_marker_carry: [96]u8 = undefined,
    pty_write_marker_carry_len: usize = 0,
    clients: std.ArrayList(*Client) = .empty,
    labels: std.StringHashMapUnmanaged([]u8) = .empty,
    // This control which client is the leader.  The leader controls terminal state and
    // cols/rows of session.
    leader_client_fd: ?i32 = null,
    running: bool = true,
    pid: i32 = undefined,
    command: ?[]const []const u8 = null,
    cwd: []const u8 = "",
    has_pty_output: bool = false,
    has_had_client: bool = false,
    has_terminal_client: bool = false, // true only after a real attach (.Init received)
    created_at: u64, // unix timestamp (ns)
    is_task_mode: bool = false, // flag for when session is run as a task
    task_exit_code: ?u8 = null, // null = running or n/a, set when task completes
    task_ended_at: ?u64 = null, // timestamp when task exited
    pty_fd: i32 = -1, // set by daemonLoop so handleRun can probe the foreground process
    shell: []const u8 = "/bin/sh",
    /// Immutable for the lifetime of a session daemon.
    log_input: bool = false,

    /// Create a Daemon. Caller is responsible for freeing all variables passed
    /// into the init fn.
    pub fn init(io: std.Io, cfg: *Cfg, sesh_name: []const u8, socket_path: []const u8) Daemon {
        return .{
            .io = io,
            .cfg = cfg,
            .session_name = sesh_name,
            .socket_path = socket_path,
            .created_at = @intCast(std.Io.Timestamp.now(io, .real).toSeconds()),
        };
    }

    pub fn deinit(self: *Daemon, gpa: std.mem.Allocator) void {
        self.clients.deinit(gpa);
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            gpa.free(entry.value_ptr.*);
        }
        self.labels.deinit(gpa);
        self.pty_write_buf.deinit(gpa);
    }

    pub fn shutdown(self: *Daemon, gpa: std.mem.Allocator) void {
        std.log.info("shutting down daemon session={s}", .{self.session_name});
        self.running = false;

        for (self.clients.items) |client| {
            client.deinit();
            gpa.destroy(client);
        }
        self.clients.clearRetainingCapacity();
    }

    pub fn closeClient(self: *Daemon, gpa: std.mem.Allocator, client: *Client, i: usize, shutdown_on_last: bool) bool {
        const fd = client.socket_fd;
        if (self.pty_write_client_fd == fd) {
            self.abandonWriteTransaction(gpa);
        }
        // leader is disconnected, remove ref and let another client claim leader on input
        if (self.leader_client_fd == client.socket_fd) {
            std.log.info(
                "unsetting leader session={s} fd={d}",
                .{ self.session_name, client.socket_fd },
            );
            self.leader_client_fd = null;
        }
        client.deinit();
        gpa.destroy(client);
        _ = self.clients.orderedRemove(i);
        std.log.info("client disconnected fd={d} remaining={d}", .{ fd, self.clients.items.len });
        if (shutdown_on_last and self.clients.items.len == 0) {
            self.shutdown(gpa);
            return true;
        }
        return false;
    }

    /// ensureSession will either create or re-use the daemon used for a session.
    /// It will spin up a unix socket, double-fork the process (so it survives
    /// the terminal dying), and automatically attach the client to the ipc unix
    /// socket.
    ///
    /// The return bool value indicates if the current process is the daemon
    /// or the client since they have different behaviors post-fork.
    ///
    /// E.g. If it's the client process then we need to connect to the unix socket
    /// and run the clientLoop.  If it's the daemon then we need to bail since
    /// the daemonLoop is created inside this fn and when it returns that means
    /// the daemon stopped and needs to exit.
    pub fn ensureSession(self: *Daemon, io: std.Io) !bool {
        const sesh_name = self.session_name;
        std.log.info("ensure session session={s}", .{sesh_name});
        var dir = try std.Io.Dir.openDirAbsolute(io, self.cfg.socket_dir, .{});
        defer dir.close(io);

        const exists = try socket.sessionExists(io, dir, self.cfg.socket_dir, sesh_name, self.cfg.socket_mode, self.cfg.socket_owner);
        // if daemon is gone then we flip this to true
        var should_create = !exists;

        if (exists) {
            if (ipc.connectSession(self.socket_path, self.cfg.socket_mode, self.cfg.socket_owner)) |fd| {
                lib_posix.close(fd);
                if (self.command != null) {
                    std.log.warn(
                        "session already exists, ignoring command session={s}",
                        .{sesh_name},
                    );
                }
            } else |err| switch (err) {
                // Daemon is definitively gone: safe to replace.
                error.ConnectionRefused => {
                    socket.cleanupStaleSocket(io, dir, self.cfg.socket_dir, sesh_name, self.cfg.socket_mode, self.cfg.socket_owner);
                    should_create = true;
                },
                // Connect failed for an unusual reason. The check is only to
                // decide create-vs-attach; the socket file exists, so proceed
                // to attach rather than fail or orphan.
                else => {
                    std.log.warn(
                        "connect failed ({s}), proceeding to attach session={s}",
                        .{ @errorName(err), sesh_name },
                    );
                },
            }
        }

        if (!should_create) {
            return false;
        }

        return self.run(io, dir, sesh_name);
    }

    fn run(self: *Daemon, io: std.Io, dir: std.Io.Dir, sesh_name: []const u8) !bool {
        std.log.info("creating session={s}", .{sesh_name});

        // Validate or securely create the per-session log while stderr still
        // reaches the initiating user. The same path is reopened and
        // revalidated after fork for the daemon's lifetime and rotations.
        var session_log_name_buf: [4096]u8 = undefined;
        const session_log_name = try std.fmt.bufPrint(
            &session_log_name_buf,
            "{s}.log",
            .{sesh_name},
        );
        var session_log_path_buf: [4096]u8 = undefined;
        var session_log_path_fba = std.heap.FixedBufferAllocator.init(&session_log_path_buf);
        const session_log_path = try std.fs.path.join(
            session_log_path_fba.allocator(),
            &.{ self.cfg.log_dir, session_log_name },
        );
        try log.preflight(io, session_log_path, self.cfg.log_mode, self.cfg.log_owner);

        const server_sock_fd: lib_posix.socket_t = try socket.createSocket(self.socket_path, self.cfg.socket_mode, self.cfg.socket_owner);
        const log_fd = log.log_system.file.?.handle;

        var keep_fds_open = [_]i32{ server_sock_fd, dir.handle, log_fd };
        const cmd = try daemonize.createCmdZ(self.shell, self.is_task_mode, self.command);
        const pty_info = daemonize.daemonize(
            sesh_name,
            cmd,
            &keep_fds_open,
        ) catch |err| {
            switch (err) {
                error.IsClientProc => {
                    // send a msg to the client that the session was created.
                    var w_buf: [2048]u8 = undefined;
                    var w = std.Io.File.stdout().writer(io, &w_buf);
                    try w.interface.print("session \"{s}\" created\n", .{sesh_name});
                    try w.interface.flush();
                    lib_posix.close(server_sock_fd);
                    return false;
                },
                else => {
                    lib_posix.close(server_sock_fd);
                    dir.deleteFile(io, self.session_name) catch {};
                    return err;
                },
            }
        };
        // =======
        // WARNING: cannot use upstream allocator or io after this point since
        // we forked the process and there's a risk of a mutex (e.g. thread-safe
        // allocator) being locked by a thread prior to fork which can cause a
        // deadlock.
        // =======

        self.pid = pty_info.pid;

        var threaded: std.Io.Threaded = .init_single_threaded;
        defer threaded.deinit();
        const new_io = threaded.io();

        const gpa: std.mem.Allocator = blk: {
            if (builtin.mode == .Debug) {
                const GPA = std.heap.DebugAllocator(.{});
                const Static = struct {
                    var gpa: GPA = .{};
                };
                break :blk Static.gpa.allocator();
            }
            break :blk std.heap.c_allocator;
        };

        defer {
            // Close and unlink the listen socket BEFORE handleKill()'s
            // 500ms SIGHUP->SIGKILL grace sleep. Otherwise a `zmx run`
            // for the same name issued in that window will hang waiting
            // for a connect.
            lib_posix.close(server_sock_fd);
            std.log.info("deleting socket file session={s}", .{sesh_name});
            dir.deleteFile(new_io, sesh_name) catch |err| {
                std.log.warn("failed to delete socket file err={s}", .{@errorName(err)});
            };
            self.handleKill(gpa, new_io);
            self.deinit(gpa);
            lib_posix.close(pty_info.master_fd);
            _ = lib_posix.waitpid(self.pid, 0);
        }

        // Keep both buffers alive for the full daemon loop: LogSystem retains
        // the path for secure rotation/reopen operations.
        log.log_system.deinit();
        try log.log_system.init(new_io, session_log_path, self.cfg.log_mode, self.cfg.log_owner);

        self.io = new_io;
        try daemonLoop(self, gpa, new_io, server_sock_fd, pty_info.master_fd);
        std.log.info("daemon loop shutdown", .{});
        return true;
    }

    fn setLeader(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        std.log.info("setting new leader client_fd={d}", .{client.socket_fd});
        self.leader_client_fd = client.socket_fd;
        // Send a resize message to the client so it can send us back their window size
        // so we can resize the pty and ghostty state.
        try client.appendMessage(gpa, .Resize, "");
    }

    fn inputPollTimeout(self: *Daemon, io: std.Io) i32 {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        var timeout: i32 = -1;
        if (self.pty_write_deadline) |deadline| {
            const remaining_ns = deadline.nanoseconds - now;
            timeout = if (remaining_ns <= 0)
                0
            else
                @intCast(@max(1, @divTrunc(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
        }
        for (self.clients.items) |client| {
            const deadline = client.pending_input_deadline orelse continue;
            const remaining_ns = deadline.nanoseconds - now;
            const remaining_ms: i32 = if (remaining_ns <= 0)
                0
            else
                @intCast(@max(1, @divTrunc(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
            if (timeout < 0 or remaining_ms < timeout) timeout = remaining_ms;
        }
        return timeout;
    }

    fn expectedWriteMarker(self: *const Daemon, kind: u8, buf: []u8) []const u8 {
        return std.fmt.bufPrint(
            buf,
            WRITE_MARKER_PREFIX ++ "{s}:{c}" ++ WRITE_MARKER_SUFFIX,
            .{ self.pty_write_token[0..], kind },
        ) catch unreachable;
    }

    fn observeWriteMarker(self: *Daemon, gpa: std.mem.Allocator, data: []const u8) !void {
        if (self.pty_write_client_fd == null or !self.pty_write_waiting_for_marker) {
            self.pty_write_marker_carry_len = 0;
            return;
        }

        var scan: [4096 + 96]u8 = undefined;
        const scan_len = self.pty_write_marker_carry_len + data.len;
        @memcpy(scan[0..self.pty_write_marker_carry_len], self.pty_write_marker_carry[0..self.pty_write_marker_carry_len]);
        @memcpy(scan[self.pty_write_marker_carry_len..scan_len], data);

        var marker_buf: [96]u8 = undefined;
        if (self.pty_write_transaction_remaining > 0) {
            const marker = self.expectedWriteMarker('N', &marker_buf);
            if (std.mem.indexOf(u8, scan[0..scan_len], marker) != null) {
                self.pty_write_waiting_for_marker = false;
                self.pty_write_marker_carry_len = 0;
                const now = std.Io.Timestamp.now(self.io, .awake);
                self.pty_write_deadline = .{ .nanoseconds = now.nanoseconds + 4 * std.time.ns_per_s };
                return;
            }
        } else {
            const done_marker = self.expectedWriteMarker('D', &marker_buf);
            if (std.mem.indexOf(u8, scan[0..scan_len], done_marker) != null) {
                self.pty_write_marker_carry_len = 0;
                try self.finishWriteTransaction(gpa, true);
                return;
            }
            const failed_marker = self.expectedWriteMarker('F', &marker_buf);
            if (std.mem.indexOf(u8, scan[0..scan_len], failed_marker) != null) {
                self.pty_write_marker_carry_len = 0;
                try self.finishWriteTransaction(gpa, false);
                return;
            }
        }

        const keep = @min(self.pty_write_marker_carry.len, scan_len);
        @memcpy(self.pty_write_marker_carry[0..keep], scan[scan_len - keep .. scan_len]);
        self.pty_write_marker_carry_len = keep;
    }

    fn finishWriteTransaction(self: *Daemon, gpa: std.mem.Allocator, success: bool) !void {
        const client_fd = self.pty_write_client_fd;
        self.pty_write_transaction_remaining = 0;
        self.pty_write_waiting_for_marker = false;
        self.pty_write_client_fd = null;
        self.pty_write_deadline = null;
        self.pty_write_marker_carry_len = 0;

        const fd = client_fd orelse return;
        for (self.clients.items) |client| {
            if (client.socket_fd != fd) continue;
            if (success) {
                try client.appendMessage(gpa, .Ack, "");
                self.has_had_client = true;
            } else {
                try client.appendMessage(gpa, .RequestRejected, "remote shell did not complete the write transaction");
            }
            return;
        }
    }

    fn abandonWriteTransaction(self: *Daemon, gpa: std.mem.Allocator) void {
        const unsent = @min(self.pty_write_transaction_remaining, self.pty_write_buf.items.len);
        if (unsent > 0) {
            self.pty_write_buf.replaceRange(gpa, 0, unsent, &[_]u8{}) catch unreachable;
        }
        self.pty_write_transaction_remaining = 0;
        self.pty_write_waiting_for_marker = false;
        self.pty_write_client_fd = null;
        self.pty_write_deadline = null;
        self.pty_write_marker_carry_len = 0;
    }

    fn expireWriteTransaction(self: *Daemon, gpa: std.mem.Allocator, io: std.Io) !void {
        const deadline = self.pty_write_deadline orelse return;
        if (deadline.nanoseconds > std.Io.Timestamp.now(io, .awake).nanoseconds) return;

        const client_fd = self.pty_write_client_fd;
        self.abandonWriteTransaction(gpa);
        const fd = client_fd orelse return;
        for (self.clients.items) |client| {
            if (client.socket_fd == fd) {
                try client.appendMessage(gpa, .RequestRejected, "remote shell did not acknowledge the write transaction");
                return;
            }
        }
    }

    fn flushExpiredPendingInput(self: *Daemon, gpa: std.mem.Allocator, io: std.Io) !void {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        for (self.clients.items) |client| {
            const deadline = client.pending_input_deadline orelse continue;
            if (deadline.nanoseconds > now) continue;
            client.pending_input_deadline = null;
            client.input_classifier.finish();
            client.input_classifier.user_input = false;
            if (client.pending_input.items.len == 0) continue;
            try self.setLeader(gpa, client);
            _ = self.queuePtyInput(gpa, client.pending_input.items);
            client.pending_input.clearRetainingCapacity();
        }
    }

    const PTY_WRITE_BUF_MAX = 256 * 1024;

    /// Queue bytes for the PTY's stdin. Flushed by daemonLoop on POLLOUT.
    /// Drops the payload if the buffer is over cap -- same failure mode as
    /// the old direct-write ptyWrite (drop on EAGAIN), just at a 64x higher
    /// threshold. Capping avoids OOM when the shell stops reading; dropping
    /// new (not old) bytes avoids tearing a partially-accepted sequence.
    fn queuePtyInput(self: *Daemon, gpa: std.mem.Allocator, data: []const u8) bool {
        if (data.len == 0) return true;
        if (data.len > PTY_WRITE_BUF_MAX or self.pty_write_buf.items.len > PTY_WRITE_BUF_MAX - data.len) {
            if (self.log_input) {
                std.log.warn("pty input dropped (buffer full, shell not reading)", .{});
            } else {
                std.log.warn("pty input dropped (buffer full, shell not reading; input logging disabled)", .{});
            }
            return false;
        }
        self.pty_write_buf.appendSlice(gpa, data) catch |err| {
            std.log.warn("pty input dropped: {s}", .{@errorName(err)});
            return false;
        };
        if (self.log_input) std.log.warn("PTY INPUT (explicitly enabled) data={x}", .{data});
        return true;
    }

    pub fn handleInput(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        if (!try self.requireInputPolicy(gpa, client)) return;
        // client is leader, send entire payload (ansi escape codes + text)
        if (self.leader_client_fd == client.socket_fd) {
            _ = self.queuePtyInput(gpa, payload);
            return;
        }

        // check if leader needs to be updated by detecting any user input
        client.pending_input.appendSlice(gpa, payload) catch {
            client.input_classifier.finish();
            client.pending_input.clearRetainingCapacity();
            client.pending_input_deadline = null;
            std.log.warn("input classification buffer dropped", .{});
            return;
        };
        client.input_classifier.feed(payload);
        if (client.input_classifier.user_input) {
            client.input_classifier.user_input = false;
            try self.setLeader(gpa, client);
            _ = self.queuePtyInput(gpa, client.pending_input.items);
            client.pending_input.clearRetainingCapacity();
            client.pending_input_deadline = null;
        } else if (client.input_classifier.pending_len > 0) {
            // Retain only the unfinished item. Completed mouse/focus reports
            // remain read-only, while a split keyboard sequence can be sent
            // intact if its continuation claims leadership.
            const pending = client.input_classifier.pending[0..client.input_classifier.pending_len];
            client.pending_input.clearRetainingCapacity();
            try client.pending_input.appendSlice(gpa, pending);
            if (client.pending_input_deadline == null) {
                const now = std.Io.Timestamp.now(self.io, .awake);
                client.pending_input_deadline = .{ .nanoseconds = now.nanoseconds + 50 * std.time.ns_per_ms };
            }
        } else {
            client.pending_input.clearRetainingCapacity();
            client.pending_input_deadline = null;
        }
    }

    /// Queue input from `zmx send` without changing interactive client leadership.
    pub fn handleSend(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        if (!try self.requireInputPolicy(gpa, client)) return;
        _ = self.queuePtyInput(gpa, payload);
    }

    fn handleInputPolicy(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        if (payload.len != @sizeOf(ipc.InputPolicy)) {
            client.input_policy_ack = null;
            try client.appendMessage(gpa, .InputPolicyMismatch, "invalid input policy declaration");
        } else {
            const declared = std.mem.bytesToValue(ipc.InputPolicy, payload).value();
            if (declared != null and declared.? == self.log_input) {
                client.input_policy_ack = declared;
                try client.appendMessage(gpa, .Ack, "");
            } else {
                client.input_policy_ack = null;
                try client.appendMessage(gpa, .InputPolicyMismatch, "session input logging policy differs; use --log-input only for logging-enabled sessions");
            }
        }
    }

    fn requireInputPolicy(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !bool {
        if (client.input_policy_ack == self.log_input) return true;
        try client.appendMessage(gpa, .InputPolicyMismatch, "input rejected: logging policy was not acknowledged");
        return false;
    }

    pub fn handleSwitch(self: *Daemon, gpa: std.mem.Allocator, session_name: []const u8) !void {
        const target = ipc.parseSwitchTarget(session_name) catch {
            std.log.warn("rejected invalid switch target", .{});
            return;
        };
        socket.validateCanonicalSessionName(self.cfg.socket_dir, target.name) catch {
            std.log.warn("rejected invalid switch target", .{});
            return;
        };
        for (self.clients.items) |client| {
            if (self.leader_client_fd == client.socket_fd) {
                client.appendMessage(gpa, .Switch, session_name) catch |err| {
                    std.log.warn(
                        "failed to buffer terminal state for client err={s}",
                        .{@errorName(err)},
                    );
                };
                return;
            }
        }
        std.log.warn("ignored switch request without a leader", .{});
    }

    pub fn handleInit(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        if (payload.len != @sizeOf(ipc.Resize)) return;

        // Serialize terminal state BEFORE resize to capture correct cursor position.
        // Resizing triggers reflow which can move the cursor, and the shell's
        // SIGWINCH-triggered redraw will run after our snapshot is sent.
        // Only serialize on re-attach (has_had_client), not first attach, to avoid
        // interfering with shell initialization (DA1 queries, etc.)
        if (self.has_pty_output and self.has_had_client) {
            const cursor = &term.screens.active.cursor;
            std.log.debug(
                "cursor before serialize: x={d} y={d} pending_wrap={}",
                .{ cursor.x, cursor.y, cursor.pending_wrap },
            );
            if (util.serializeTerminalState(gpa, term)) |term_output| {
                std.log.debug("serialize terminal state", .{});
                // Rewrite OSC 133;A to include redraw=0 so the outer terminal
                // does not clear prompt lines on resize (issue #111).
                const restore_data = util.rewritePromptRedraw(gpa, term_output) orelse term_output;
                defer gpa.free(term_output);
                defer if (restore_data.ptr != term_output.ptr) gpa.free(restore_data);
                client.appendLargeMessage(gpa, .Output, restore_data) catch |err| {
                    std.log.warn(
                        "failed to buffer terminal state for client err={s}",
                        .{@errorName(err)},
                    );
                };
            }
        }

        // no leader is set so set one
        if (self.leader_client_fd == null) {
            try self.setLeader(gpa, client);
        }

        // only resize if leader
        if (self.leader_client_fd == client.socket_fd) {
            const resize = std.mem.bytesToValue(ipc.Resize, payload);
            var ws: cross.c.struct_winsize = .{
                .ws_row = resize.rows,
                .ws_col = resize.cols,
                .ws_xpixel = resize.xpixel,
                .ws_ypixel = resize.ypixel,
            };
            _ = cross.c.ioctl(pty_fd, cross.c.TIOCSWINSZ, &ws);
            // Disable prompt_redraw before resize. The daemon's internal terminal
            // would otherwise clear prompt lines expecting the shell to redraw them,
            // but the shell's redraw goes to the PTY (forwarded to clients), not to
            // this daemon terminal. The clearing corrupts the daemon's snapshot state.
            const saved_prompt_redraw = term.flags.shell_redraws_prompt;
            term.flags.shell_redraws_prompt = .false;
            defer term.flags.shell_redraws_prompt = saved_prompt_redraw;
            const opts = ghostty_vt.Terminal.Resize{
                .cols = resize.cols,
                .rows = resize.rows,
            };
            try term.resize(gpa, opts);

            // Mark that we've had a client init, so subsequent clients get terminal state
            self.has_had_client = true;
            self.has_terminal_client = true;

            std.log.debug("init resize rows={d} cols={d}", .{ resize.rows, resize.cols });
        }
    }

    pub fn handleResize(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        if (payload.len != @sizeOf(ipc.Resize)) return;
        if (self.leader_client_fd == null) {
            try self.setLeader(gpa, client);
        }
        // only leader can resize
        if (self.leader_client_fd != client.socket_fd) return;

        const resize = std.mem.bytesToValue(ipc.Resize, payload);
        var ws: cross.c.struct_winsize = .{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.xpixel,
            .ws_ypixel = resize.ypixel,
        };
        _ = cross.c.ioctl(pty_fd, cross.c.TIOCSWINSZ, &ws);
        // Disable prompt_redraw before resize (same rationale as handleInit).
        const saved_prompt_redraw = term.flags.shell_redraws_prompt;
        term.flags.shell_redraws_prompt = .false;
        defer term.flags.shell_redraws_prompt = saved_prompt_redraw;
        const opts = ghostty_vt.Terminal.Resize{
            .cols = resize.cols,
            .rows = resize.rows,
        };
        try term.resize(gpa, opts);
        std.log.debug("resize rows={d} cols={d}", .{ resize.rows, resize.cols });
    }

    pub fn handleDetach(self: *Daemon, gpa: std.mem.Allocator, client: *Client, i: usize) void {
        std.log.info("client detach session={s} fd={d}", .{ self.session_name, client.socket_fd });
        _ = self.closeClient(gpa, client, i, false);
    }

    pub fn handleDetachAll(self: *Daemon, gpa: std.mem.Allocator) void {
        std.log.info("detach all clients={d}", .{self.clients.items.len});
        for (self.clients.items) |client_to_close| {
            client_to_close.deinit();
            gpa.destroy(client_to_close);
        }
        self.clients.clearRetainingCapacity();
    }

    pub fn handleKill(self: *Daemon, gpa: std.mem.Allocator, io: std.Io) void {
        std.log.info("kill received session={s}", .{self.session_name});
        self.shutdown(gpa);
        // gracefully shutdown shell processes, shells tend to ignore SIGTERM so we send SIGHUP
        // instead
        //   https://www.gnu.org/software/bash/manual/html_node/Signals.html
        // negative pid means kill process and children
        std.log.info("sending SIGHUP session={s} pid={d}", .{ self.session_name, self.pid });
        lib_posix.kill(-self.pid, lib_posix.SIG.HUP) catch |err| {
            std.log.warn("failed to send SIGHUP to pty child err={s}", .{@errorName(err)});
        };
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(500), .real) catch unreachable;
        lib_posix.kill(-self.pid, lib_posix.SIG.KILL) catch |err| {
            std.log.warn("failed to send SIGKILL to pty child err={s}", .{@errorName(err)});
        };
    }

    pub fn handleInfo(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        // zeroes() so asBytes() doesn't ship struct padding + unused cmd/cwd
        // tail bytes (daemon stack contents) to clients.
        var info = std.mem.zeroes(ipc.Info);
        info.clients_len = self.clients.items.len - 1;
        info.pid = self.pid;
        info.created_at = self.created_at;
        info.task_ended_at = self.task_ended_at orelse 0;
        info.task_exit_code = self.task_exit_code orelse 0;

        // Build command string from args, re-quoting args that contain
        // shell-special characters so the displayed command is copy-pasteable.
        const cur_cmd = self.command;
        if (cur_cmd) |args| {
            for (args, 0..) |arg, i| {
                const quoted = if (util.shellNeedsQuoting(arg))
                    util.shellQuote(gpa, arg) catch null
                else
                    null;
                defer if (quoted) |q| gpa.free(q);
                const src = quoted orelse arg;

                const need = src.len + @as(usize, if (i > 0) 1 else 0);
                if (info.cmd_len + need > ipc.MAX_CMD_LEN) {
                    const ellipsis = "...";
                    if (info.cmd_len + ellipsis.len <= ipc.MAX_CMD_LEN) {
                        @memcpy(info.cmd[info.cmd_len..][0..ellipsis.len], ellipsis);
                        info.cmd_len += ellipsis.len;
                    }
                    break;
                }

                if (i > 0) {
                    info.cmd[info.cmd_len] = ' ';
                    info.cmd_len += 1;
                }
                @memcpy(info.cmd[info.cmd_len..][0..src.len], src);
                info.cmd_len += @intCast(src.len);
            }
        }

        info.cwd_len = @intCast(@min(self.cwd.len, ipc.MAX_CWD_LEN));
        @memcpy(info.cwd[0..info.cwd_len], self.cwd[0..info.cwd_len]);

        try client.appendMessage(gpa, .Info, std.mem.asBytes(&info));
    }

    pub fn handleHistory(
        _: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        const format: util.HistoryFormat = if (payload.len == 0)
            .plain
        else switch (payload[0]) {
            0 => .plain,
            1 => .vt,
            2 => .html,
            else => {
                std.log.warn("rejected invalid history format", .{});
                return;
            },
        };
        if (util.serializeTerminal(gpa, term, format)) |output| {
            defer gpa.free(output);
            try client.appendLargeMessage(gpa, .History, output);
        } else {
            try client.appendLargeMessage(gpa, .History, "");
        }
    }

    pub fn handleRun(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        if (!try self.requireInputPolicy(gpa, client)) return;
        if (payload.len == 0) return;

        const cmd = payload;

        // Chain the exit marker with `;` on the same line. `$?` captures the
        // exit code of the command (not the `;`). The sole exception is when
        // the command contains a heredoc (`<<`), the delimiter must be alone
        // on its line, so the marker goes on the next line instead.
        const single_line_marker = "; echo ZMX_TASK_COMPLETED:$?\r";
        const heredoc_marker = "\r\necho ZMX_TASK_COMPLETED:$?\r";
        const uses_heredoc = std.mem.indexOf(u8, cmd, "<<") != null;

        var pty_command = std.ArrayList(u8).empty;
        defer pty_command.deinit(gpa);
        if (cmd.len > 0 and cmd[cmd.len - 1] == '\r') {
            try pty_command.appendSlice(gpa, cmd[0 .. cmd.len - 1]);
        } else {
            try pty_command.appendSlice(gpa, cmd);
        }
        try pty_command.appendSlice(gpa, if (uses_heredoc) heredoc_marker else single_line_marker);
        if (!self.queuePtyInput(gpa, pty_command.items)) {
            try client.appendMessage(gpa, .RequestRejected, "PTY input queue is busy or request is too large");
            return;
        }

        // Reset task tracking only after the command is accepted, so a busy
        // queue cannot erase the prior task result or change session mode.
        self.task_exit_code = null;
        self.task_ended_at = null;
        self.is_task_mode = true;
        try client.appendMessage(gpa, .Ack, "");
        self.has_had_client = true;
    }

    pub fn handleOutput(self: *Daemon, gpa: std.mem.Allocator, payload: []const u8, vt_stream: anytype) !void {
        vt_stream.nextSlice(payload);
        self.has_pty_output = true;
        for (self.clients.items) |client| {
            try client.appendMessage(gpa, .Output, payload);
        }
        if (self.clients.items.len > 0) {
            lib_posix.kill(self.pid, lib_posix.SIG.WINCH) catch |err| {
                std.log.warn("failed to send SIGWINCH err={s}", .{@errorName(err)});
            };
        }
    }

    pub fn handleWrite(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        if (!try self.requireInputPolicy(gpa, client)) return;
        // Wire format: [u32 path len][path bytes][file content]
        if (payload.len < @sizeOf(u32)) {
            std.log.warn("rejected invalid write payload", .{});
            return;
        }
        const path_len: usize = @intCast(std.mem.bytesToValue(u32, payload[0..@sizeOf(u32)]));
        if (path_len > payload.len - @sizeOf(u32)) {
            std.log.warn("rejected invalid write payload", .{});
            return;
        }
        const file_path = payload[@sizeOf(u32)..][0..path_len];
        const file_content = payload[@sizeOf(u32) + path_len ..];

        // Inject file creation through the PTY so it works over SSH.
        // Base64-encode content and pipe through printf | base64 -d > file.
        if (path_len == 0 or
            path_len > ipc.MAX_WRITE_PATH_LEN or
            std.mem.indexOfScalar(u8, file_path, 0) != null or
            file_content.len > ipc.MAX_WRITE_CONTENT_LEN)
        {
            try client.appendMessage(gpa, .RequestRejected, "write path or content exceeds the supported limit");
            return;
        }

        // Only one write transaction may own the front of the PTY queue. This
        // makes its full userspace acceptance atomic and lets every generated
        // line wait for a randomized receipt from the remote shell.
        if (self.pty_write_client_fd != null or self.pty_write_buf.items.len != 0) {
            try client.appendMessage(gpa, .RequestRejected, "PTY input queue is busy");
            return;
        }

        var pty_command = std.ArrayList(u8).empty;
        defer pty_command.deinit(gpa);
        var random_token: [16]u8 = undefined;
        try self.io.randomSecure(&random_token);
        var token: [32]u8 = undefined;
        const hex = "0123456789abcdef";
        for (random_token, 0..) |byte, i| {
            token[i * 2] = hex[byte >> 4];
            token[i * 2 + 1] = hex[byte & 0x0f];
        }

        const content_chunk_size = 2880; // divisible by 3 -> 3840 base64 bytes
        const encoded_path_len = std.base64.standard.Encoder.calcSize(file_path.len);
        const encoded_path = try gpa.alloc(u8, encoded_path_len);
        defer gpa.free(encoded_path);
        _ = std.base64.standard.Encoder.encode(encoded_path, file_path);

        try pty_command.appendSlice(gpa, "zmx_write_path_b64=''");
        try appendReceiptedWriteLine(gpa, &pty_command, &token);
        const path_chunk_size = 3000;
        var path_offset: usize = 0;
        while (path_offset < encoded_path.len) {
            const path_end = @min(path_offset + path_chunk_size, encoded_path.len);
            try pty_command.appendSlice(gpa, "zmx_write_path_b64=\"${zmx_write_path_b64}");
            try pty_command.appendSlice(gpa, encoded_path[path_offset..path_end]);
            try pty_command.append(gpa, '"');
            try appendReceiptedWriteLine(gpa, &pty_command, &token);
            path_offset = path_end;
        }
        // The trailing sentinel prevents command substitution from stripping
        // valid newline bytes at the end of the decoded Unix path.
        try pty_command.appendSlice(gpa, "zmx_write_path=$(printf '%s' \"$zmx_write_path_b64\" | base64 -d; printf x); zmx_write_path=${zmx_write_path%x}");
        try appendReceiptedWriteLine(gpa, &pty_command, &token);
        try pty_command.appendSlice(gpa, ": > \"$zmx_write_path\"");
        try appendReceiptedWriteLine(gpa, &pty_command, &token);

        var offset: usize = 0;
        while (offset < file_content.len) {
            const end = @min(offset + content_chunk_size, file_content.len);
            const chunk = file_content[offset..end];

            const encoded_len = std.base64.standard.Encoder.calcSize(chunk.len);
            const encoded = try gpa.alloc(u8, encoded_len);
            defer gpa.free(encoded);
            _ = std.base64.standard.Encoder.encode(encoded, chunk);

            try pty_command.appendSlice(gpa, "printf '%s' '");
            try pty_command.appendSlice(gpa, encoded);
            try pty_command.appendSlice(gpa, "' | base64 -d >> \"$zmx_write_path\"");
            try appendReceiptedWriteLine(gpa, &pty_command, &token);

            offset = end;
        }
        const expected_size = try std.fmt.allocPrint(gpa, "{d}", .{file_content.len});
        defer gpa.free(expected_size);
        try pty_command.appendSlice(gpa, "zmx_write_size=$(wc -c < \"$zmx_write_path\" 2>/dev/null) || zmx_write_size=-1; if [ \"$zmx_write_size\" -eq ");
        try pty_command.appendSlice(gpa, expected_size);
        try pty_command.appendSlice(gpa, " ] 2>/dev/null; then unset zmx_write_path zmx_write_path_b64 zmx_write_size; ");
        try appendShellWriteMarker(gpa, &pty_command, &token, 'D');
        try pty_command.appendSlice(gpa, "; else unset zmx_write_path zmx_write_path_b64 zmx_write_size; ");
        try appendShellWriteMarker(gpa, &pty_command, &token, 'F');
        try pty_command.appendSlice(gpa, "; fi\r");

        if (!self.queuePtyInput(gpa, pty_command.items)) {
            try client.appendMessage(gpa, .RequestRejected, "PTY input queue is busy or request is too large");
            return;
        }

        self.pty_write_transaction_remaining = pty_command.items.len;
        self.pty_write_waiting_for_marker = false;
        self.pty_write_client_fd = client.socket_fd;
        self.pty_write_token = token;
        const now = std.Io.Timestamp.now(self.io, .awake);
        self.pty_write_deadline = .{ .nanoseconds = now.nanoseconds + 4 * std.time.ns_per_s };
    }

    fn handleLabelGet(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        const out = try label.labelsToU8(gpa, self.labels);
        defer gpa.free(out);
        try client.appendMessage(gpa, .LabelData, out);
    }

    fn handleLabelSet(self: *Daemon, gpa: std.mem.Allocator, client: *Client, labels: []const u8) !void {
        std.log.info("handle label set payload={s}", .{labels});

        var kvs = label.LabelIterator.init(labels);
        while (kvs.next()) |kv| {
            if (kv.value.len == 0) {
                if (self.labels.fetchRemove(kv.key)) |existing| {
                    gpa.free(existing.key);
                    gpa.free(existing.value);
                }
                continue;
            }

            const owned_key = try gpa.dupe(u8, kv.key);
            errdefer gpa.free(owned_key);
            const owned_value = try gpa.dupe(u8, kv.value);
            errdefer gpa.free(owned_value);
            if (try self.labels.fetchPut(gpa, owned_key, owned_value)) |existing| {
                // fetchPut does NOT replace the key in the map, the old
                // key pointer stays. So free the new (unused) key and the
                // old value.
                gpa.free(owned_key);
                gpa.free(existing.value);
            }
        }

        try client.appendMessage(gpa, .Ack, "");
    }

    fn handleLabelClear(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            gpa.free(entry.value_ptr.*);
        }
        self.labels.clearRetainingCapacity();
        try client.appendMessage(gpa, .Ack, "");
    }
};

test "send queues PTY input without changing leader" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .clients = .empty,
        .leader_client_fd = 42,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = 7,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    try daemon.handleSend(alloc, &client, "hello");

    try std.testing.expectEqual(@as(?i32, 42), daemon.leader_client_fd);
    try std.testing.expectEqualStrings("hello", daemon.pty_write_buf.items);
}

test "input policy mismatch rejects bytes before PTY queue" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .io = std.testing.io,
        .cfg = undefined,
        .session_name = "test",
        .socket_path = "",
        .created_at = 0,
        .log_input = true,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = 7,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    try daemon.handleSend(alloc, &client, "secret");

    try std.testing.expectEqual(@as(usize, 0), daemon.pty_write_buf.items.len);
    try std.testing.expect(client.has_pending_output);
    const header = std.mem.bytesToValue(ipc.Header, client.write_buf.items[0..@sizeOf(ipc.Header)]);
    try std.testing.expectEqual(ipc.Tag.InputPolicyMismatch, header.tag);
}

test "malformed write length is rejected before PTY queue" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .session_name = "test",
        .socket_path = "",
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = 7,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    const malicious_len: u32 = std.math.maxInt(u32);
    try daemon.handleWrite(alloc, &client, std.mem.asBytes(&malicious_len));

    try std.testing.expectEqual(@as(usize, 0), daemon.pty_write_buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.write_buf.items.len);
}

test "daemon input logging policy defaults off and is immutable state" {
    const daemon = Daemon.init(std.testing.io, undefined, "test", "");
    try std.testing.expect(!daemon.log_input);
}

test "split keyboard input claims leadership and queues the complete sequence" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .io = std.testing.io,
        .cfg = undefined,
        .session_name = "test",
        .socket_path = "",
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = 7,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    try daemon.handleInput(alloc, &client, "\x1b[1;");
    try std.testing.expectEqual(@as(?i32, null), daemon.leader_client_fd);
    try std.testing.expectEqual(@as(usize, 0), daemon.pty_write_buf.items.len);

    try daemon.handleInput(alloc, &client, "5C");
    try std.testing.expectEqual(@as(?i32, 7), daemon.leader_client_fd);
    try std.testing.expectEqualStrings("\x1b[1;5C", daemon.pty_write_buf.items);
}

test "standalone escape from nonleader claims leadership after deadline" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .io = std.testing.io,
        .cfg = undefined,
        .session_name = "test",
        .socket_path = "",
        .created_at = 0,
        .leader_client_fd = 99,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    defer daemon.clients.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = 7,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);
    try daemon.clients.append(alloc, &client);

    try daemon.handleInput(alloc, &client, "\x1b");
    try std.testing.expectEqual(@as(?i32, 99), daemon.leader_client_fd);
    try std.testing.expectEqual(@as(usize, 0), daemon.pty_write_buf.items.len);

    client.pending_input_deadline = .zero;
    try daemon.flushExpiredPendingInput(alloc, std.testing.io);
    try std.testing.expectEqual(@as(?i32, 7), daemon.leader_client_fd);
    try std.testing.expectEqualStrings("\x1b", daemon.pty_write_buf.items);
}

test "slow client output queue is bounded" {
    try std.testing.expect(Client.messageFits(0, Client.BACKLOG_MAX));
    try std.testing.expect(!Client.messageFits(1, Client.BACKLOG_MAX));
    try std.testing.expect(!Client.messageFits(0, Client.BACKLOG_MAX + 1));
}

test "ordinary output remains bounded alongside one large response" {
    const alloc = std.testing.allocator;
    var client = Client{
        .alloc = alloc,
        .socket_fd = -1,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    const large = try alloc.alloc(u8, 1024 * 1024);
    defer alloc.free(large);
    @memset(large, 'h');
    try client.appendLargeMessage(alloc, .History, large);
    const large_frame_len = client.large_frame_remaining;

    var output: [4096]u8 = @splat('o');
    while (!client.close_requested) {
        try client.appendMessage(alloc, .Output, &output);
    }

    try std.testing.expect(client.ordinaryBacklogLen() <= Client.BACKLOG_MAX);
    try std.testing.expectEqual(large_frame_len, client.large_frame_remaining);
    try std.testing.expect(client.write_buf.items.len <= large_frame_len + Client.BACKLOG_MAX);
}

test "rejected run preserves previous task state" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .session_name = "test",
        .socket_path = "",
        .created_at = 0,
        .is_task_mode = false,
        .task_exit_code = 23,
        .task_ended_at = 456,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    try daemon.pty_write_buf.resize(alloc, Daemon.PTY_WRITE_BUF_MAX);

    var client = Client{
        .alloc = alloc,
        .socket_fd = -1,
        .read_buf = try ipc.SocketBuffer.init(alloc),
        .write_buf = .empty,
        .input_policy_ack = false,
    };
    defer client.read_buf.deinit();
    defer client.write_buf.deinit(alloc);
    defer client.pending_input.deinit(alloc);

    try daemon.handleRun(alloc, &client, "true");

    try std.testing.expect(!daemon.is_task_mode);
    try std.testing.expectEqual(@as(?u8, 23), daemon.task_exit_code);
    try std.testing.expectEqual(@as(?u64, 456), daemon.task_ended_at);
    const header = std.mem.bytesToValue(ipc.Header, client.write_buf.items[0..@sizeOf(ipc.Header)]);
    try std.testing.expectEqual(ipc.Tag.RequestRejected, header.tag);
}
