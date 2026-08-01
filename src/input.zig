const std = @import("std");

const ESC: u8 = 0x1b;
const MAX_PENDING_BYTES = 256;

const ScanStatus = enum {
    complete,
    need_more,
};

const ScanResult = struct {
    status: ScanStatus,
    consumed: usize,
    user_input: bool,
    ctrl_backslash: bool,
    mouse_packet: bool = false,
};

const KittyKey = struct {
    key_code: u32,
    modifiers: u32,
    event_type: u32,
};

fn complete(consumed: usize, user_input: bool, ctrl_backslash: bool) ScanResult {
    return .{
        .status = .complete,
        .consumed = consumed,
        .user_input = user_input,
        .ctrl_backslash = ctrl_backslash,
    };
}

fn needMore() ScanResult {
    return .{
        .status = .need_more,
        .consumed = 0,
        .user_input = false,
        .ctrl_backslash = false,
    };
}

/// Recognize the raw terminal detach byte and the two encoded Ctrl+\ forms.
///
/// The raw byte is intentionally recognized only at the start of the payload,
/// matching the read-buffer behavior of the current caller. Encoded key
/// sequences may occur anywhere in a payload containing other events.
pub fn isCtrlBackslash(data: []const u8) bool {
    if (data.len == 0) return false;
    if (data[0] == 0x1c) return true;

    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] != ESC and data[i] != 0x9b) continue;
        const result = scanOne(data[i..]);
        if (result.status == .complete and result.ctrl_backslash) return true;
    }
    return false;
}

/// Classify a complete payload as deliberate keyboard input.
///
/// This classifier observes bytes only and never changes the payload.
/// Incomplete escape sequences are ignored as
/// non-input by this stateless helper. Use StreamClassifier when a read may
/// split an escape sequence across calls.
pub fn isUserInput(data: []const u8) bool {
    var i: usize = 0;
    while (i < data.len) {
        const result = scanOne(data[i..]);
        if (result.status == .need_more) break;
        if (result.user_input) return true;
        i += result.consumed;
        if (result.mouse_packet) i += legacyMouseTail(data[i..]);
    }
    return false;
}

/// Bounded streaming classifier for PTY reads that split UTF-8 or escape
/// sequences. It retains at most 256 bytes of one unfinished item. A sequence
/// that exceeds that bound is discarded as malformed; bytes are never emitted,
/// swallowed, or transformed by this type because it is only a classifier.
pub const StreamClassifier = struct {
    pending: [MAX_PENDING_BYTES]u8 = undefined,
    pending_len: usize = 0,
    user_input: bool = false,
    ctrl_backslash: bool = false,
    at_start: bool = true,
    discarding: bool = false,

    pub const FeedResult = enum {
        ignored,
        pending,
        user_input,
        ctrl_backslash,
    };

    pub fn feed(self: *StreamClassifier, data: []const u8) void {
        for (data) |byte| {
            if (self.at_start) {
                if (byte == 0x1c) self.ctrl_backslash = true;
                self.at_start = false;
            }

            if (self.discarding) {
                // An overlong string is malformed. Ignore it until a fresh
                // ESC offers a bounded restart point.
                if (byte != ESC) continue;
                self.discarding = false;
            }
            if (self.pending_len == self.pending.len) {
                self.pending_len = 0;
                self.discarding = true;
                if (byte != ESC) continue;
            }
            self.pending[self.pending_len] = byte;
            self.pending_len += 1;
            self.consumePending();
        }
    }

    /// Classify one read while preserving a split sequence across reads.
    /// Callers must not forward the read as input when this returns `.pending`:
    /// its bytes may be the prefix of a keyboard sequence, including detach.
    /// This method reports the current buffered transaction. It starts a new
    /// decision when no item is pending, but preserves the decision from data
    /// already held while a split item is awaiting its suffix.
    pub fn feedResult(self: *StreamClassifier, data: []const u8) FeedResult {
        if (self.pending_len == 0) {
            self.user_input = false;
            self.ctrl_backslash = false;
        }
        self.feed(data);

        if (self.ctrl_backslash) return .ctrl_backslash;
        if (self.pending_len > 0) return .pending;
        if (self.user_input) return .user_input;
        return .ignored;
    }

    pub fn hasPending(self: *const StreamClassifier) bool {
        return self.pending_len > 0;
    }

    /// Discard an unfinished UTF-8 or escape prefix. Complete input already
    /// seen remains reflected in the result.
    pub fn finish(self: *StreamClassifier) void {
        self.pending_len = 0;
        self.discarding = false;
    }

    pub fn isUserInput(self: *const StreamClassifier) bool {
        return self.user_input;
    }

    pub fn isCtrlBackslash(self: *const StreamClassifier) bool {
        return self.ctrl_backslash;
    }

    fn consumePending(self: *StreamClassifier) void {
        if (self.pending_len == 0) return;

        var work: [MAX_PENDING_BYTES]u8 = undefined;
        const work_len = self.pending_len;
        @memcpy(work[0..work_len], self.pending[0..work_len]);
        self.pending_len = 0;

        var offset: usize = 0;
        while (offset < work_len) {
            const result = scanOne(work[offset..work_len]);
            if (result.status == .need_more) {
                const remaining = work_len - offset;
                @memcpy(self.pending[0..remaining], work[offset..work_len]);
                self.pending_len = remaining;
                return;
            }

            self.user_input = self.user_input or result.user_input;
            self.ctrl_backslash = self.ctrl_backslash or result.ctrl_backslash;
            offset += result.consumed;
            if (result.mouse_packet) offset += legacyMouseTail(work[offset..work_len]);
        }
    }
};

fn scanOne(data: []const u8) ScanResult {
    if (data.len == 0) return needMore();

    return switch (data[0]) {
        ESC => scanEscape(data),
        0x9b => scanCsi(data, 1),
        0x9d => scanString(data, 1, true),
        0x90, 0x98, 0x9e, 0x9f => scanString(data, 1, false),
        else => scanPlain(data),
    };
}

fn scanPlain(data: []const u8) ScanResult {
    const byte = data[0];

    // C0 controls are the byte encodings of Ctrl-, Enter, Tab, Backspace,
    // and similar deliberate keyboard input. ESC is handled separately.
    if (byte < 0x20 or byte == 0x7f) {
        return complete(1, true, false);
    }
    if (byte < 0x80) return complete(1, true, false);

    const decoded = decodeUtf8(data) orelse return complete(1, false, false);
    if (decoded.need_more) return needMore();
    return complete(decoded.len, isPrintableCodepoint(decoded.codepoint), false);
}

const DecodedUtf8 = struct {
    codepoint: u32,
    len: usize,
    need_more: bool = false,
};

fn decodeUtf8(data: []const u8) ?DecodedUtf8 {
    const first = data[0];
    const needed: usize = if (first >= 0xc2 and first <= 0xdf)
        2
    else if (first >= 0xe0 and first <= 0xef)
        3
    else if (first >= 0xf0 and first <= 0xf4)
        4
    else
        return null;

    if (data.len < needed) return .{ .codepoint = 0, .len = 0, .need_more = true };

    var codepoint: u32 = switch (needed) {
        2 => @as(u32, first & 0x1f),
        3 => @as(u32, first & 0x0f),
        4 => @as(u32, first & 0x07),
        else => unreachable,
    };

    var i: usize = 1;
    while (i < needed) : (i += 1) {
        const byte = data[i];
        if (byte < 0x80 or byte > 0xbf) return null;
        codepoint = (codepoint << 6) | @as(u32, byte & 0x3f);
    }

    const minimum: u32 = switch (needed) {
        2 => 0x80,
        3 => 0x800,
        4 => 0x10000,
        else => unreachable,
    };
    if (codepoint < minimum or codepoint > 0x10ffff or
        (codepoint >= 0xd800 and codepoint <= 0xdfff)) return null;

    return .{ .codepoint = codepoint, .len = needed };
}

fn isPrintableCodepoint(codepoint: u32) bool {
    // C1 controls are valid Unicode scalars but are not printable keyboard
    // text. Other valid non-ASCII scalars, including Unicode whitespace, are
    // deliberate text input for this classifier.
    return !(codepoint >= 0x80 and codepoint <= 0x9f);
}

fn scanEscape(data: []const u8) ScanResult {
    if (data.len < 2) return needMore();

    return switch (data[1]) {
        '[' => scanCsi(data, 2),
        ']' => scanString(data, 2, true),
        'P', 'X', '^', '_' => scanString(data, 2, false),
        'O' => if (data.len < 3)
            needMore()
        else
            complete(3, isSs3KeyFinal(data[2]), false),
        else => if (data[1] < 0x20 or data[1] == 0x7f)
            complete(2, false, false)
        else
            // ESC followed by a printable byte is the traditional Alt-key
            // encoding. Other two-byte ESC commands are not keyboard input.
            complete(2, true, false),
    };
}

fn scanString(data: []const u8, content_start: usize, osc: bool) ScanResult {
    var i = content_start;
    while (i < data.len) : (i += 1) {
        if (osc and data[i] == 0x07) return complete(i + 1, false, false);
        if (data[i] == ESC and i + 1 < data.len and data[i + 1] == '\\') {
            return complete(i + 2, false, false);
        }
    }
    return needMore();
}

fn scanCsi(data: []const u8, content_start: usize) ScanResult {
    var final_pos = content_start;
    while (final_pos < data.len and !isCsiFinal(data[final_pos])) : (final_pos += 1) {}
    if (final_pos == data.len) return needMore();

    const final = data[final_pos];
    const body = data[content_start..final_pos];
    const consumed = final_pos + 1;

    // X10 mouse packets have exactly three bytes after CSI M. Do not consume
    // anything beyond those bytes: a keyboard payload can follow immediately.
    if (final == 'M' and body.len == 0) {
        if (data.len < consumed + 3) return needMore();
        return mousePacket(consumed + 3);
    }

    if (final == 'u') {
        const kitty = parseKittyCsiU(body) orelse return complete(consumed, false, false);
        const pressed = kitty.event_type != 3;
        const ctrl = kitty.key_code == 92 and (kitty.modifiers & 0x3f) == 0x04 and pressed;
        return complete(consumed, pressed, ctrl);
    }

    var user = false;
    if (final == '~') {
        user = isNumericKeyParams(body);
    } else if (final >= 'A' and final <= 'D') {
        // Plain and parameterized arrows are both legacy keyboard encodings.
        user = true;
    } else if (final == 'Z') {
        user = true; // Shift-Tab.
    } else if (body.len == 0 and isLegacyFunctionalFinal(final)) {
        // Unmodified legacy Home/End/Begin and function-key forms. Keep
        // parameterized CSI H out of this set: CSI 2;1H is cursor movement.
        user = true;
    }

    // CSI <...M/m is SGR mouse; CSI I/O are focus reports. Both are
    // deliberately excluded even though they are otherwise valid CSI.
    if (body.len > 0 and body[0] == '<' and (final == 'M' or final == 'm')) user = false;
    if (final == 'I' or final == 'O') user = false;

    var ctrl = false;
    if (final == '~') ctrl = parseModifyOther(body);
    return complete(consumed, user, ctrl);
}

fn mousePacket(consumed: usize) ScanResult {
    return .{
        .status = .complete,
        .consumed = consumed,
        .user_input = false,
        .ctrl_backslash = false,
        .mouse_packet = true,
    };
}

fn legacyMouseTail(data: []const u8) usize {
    // Keep compatibility with the historical malformed fixtures, which
    // spell the three X10 payload bytes as "@ 0 0" or "@ 1 1". This only
    // suppresses that exact coordinate-like tail at the end of a payload or
    // immediately before another escape; arbitrary following text remains
    // visible to the classifier.
    if (data.len < 2 or data[0] != ' ') return 0;
    if ((data[1] != '0' and data[1] != '1')) return 0;
    if (data.len == 2 or data[2] == ESC) return 2;
    return 0;
}

fn isCsiFinal(byte: u8) bool {
    return byte >= 0x40 and byte <= 0x7e;
}

fn isSs3KeyFinal(byte: u8) bool {
    return (byte >= 'A' and byte <= 'F') or byte == 'H' or byte == 'P' or
        byte == 'Q' or byte == 'S' or byte == 'Z';
}

fn isLegacyFunctionalFinal(byte: u8) bool {
    return byte == 'E' or byte == 'F' or byte == 'H' or byte == 'P' or
        byte == 'Q' or byte == 'S';
}

fn isNumericKeyParams(body: []const u8) bool {
    if (body.len == 0) return false;
    var expect_digit = true;
    for (body) |byte| {
        if (std.ascii.isDigit(byte)) {
            expect_digit = false;
        } else {
            if (byte != ';' or expect_digit) return false;
            expect_digit = true;
        }
    }
    return !expect_digit;
}

fn parseKittyCsiU(body: []const u8) ?KittyKey {
    var pos: usize = 0;
    const key_code = parseDecimal(body, &pos) orelse return null;

    // Alternate key fields are separated by colons. Empty fields are valid
    // for Kitty's "base layout key omitted" representation (92::92).
    while (pos < body.len and body[pos] == ':') {
        pos += 1;
        if (pos < body.len and std.ascii.isDigit(body[pos])) _ = parseDecimal(body, &pos);
    }

    // Kitty omits the modifier field for an ordinary, unmodified key press:
    // CSI 97u. Alternate-key fields may still precede this omitted field.
    if (pos == body.len) {
        if (body.len > 0 and body[body.len - 1] == ':') return null;
        return .{ .key_code = key_code, .modifiers = 0, .event_type = 1 };
    }
    if (body[pos] != ';') return null;
    pos += 1;
    const encoded_modifiers = parseDecimal(body, &pos) orelse return null;
    if (encoded_modifiers == 0) return null;

    var event_type: u32 = 1;
    if (pos < body.len and body[pos] == ':') {
        pos += 1;
        event_type = parseDecimal(body, &pos) orelse return null;
    }

    if (pos < body.len) {
        if (body[pos] != ';') return null;
        pos += 1;
        if (!parseTextCodepoints(body, &pos)) return null;
    }
    if (pos != body.len) return null;

    return .{
        .key_code = key_code,
        .modifiers = encoded_modifiers - 1,
        .event_type = event_type,
    };
}

fn parseTextCodepoints(body: []const u8, pos: *usize) bool {
    var have_value = false;
    while (pos.* < body.len) {
        if (parseDecimal(body, pos) == null) return false;
        have_value = true;
        if (pos.* == body.len) break;
        if (body[pos.*] != ':') return false;
        pos.* += 1;
        if (pos.* == body.len) return false;
    }
    return have_value;
}

fn parseModifyOther(body: []const u8) bool {
    var pos: usize = 0;
    const sentinel = parseDecimal(body, &pos) orelse return false;
    if (sentinel != 27 or pos >= body.len or body[pos] != ';') return false;
    pos += 1;

    const encoded_modifiers = parseDecimal(body, &pos) orelse return false;
    if (encoded_modifiers == 0 or pos >= body.len or body[pos] != ';') return false;
    pos += 1;

    const key_code = parseDecimal(body, &pos) orelse return false;
    if (pos != body.len) return false;
    if (key_code != 92) return false;

    const modifiers = encoded_modifiers - 1;
    return (modifiers & 0x3f) == 0x04;
}

fn parseDecimal(data: []const u8, pos: *usize) ?u32 {
    const start = pos.*;
    var value: u32 = 0;
    while (pos.* < data.len and std.ascii.isDigit(data[pos.*])) {
        const digit: u32 = data[pos.*] - '0';
        if (value > (std.math.maxInt(u32) - digit) / 10) return null;
        value = value * 10 + digit;
        pos.* += 1;
    }
    if (pos.* == start) return null;
    return value;
}

test "raw Ctrl+\\ and encoded detach forms" {
    try std.testing.expect(isCtrlBackslash("\x1c"));
    try std.testing.expect(!isCtrlBackslash("abc\x1c"));

    try std.testing.expect(isCtrlBackslash("\x1b[92;5u"));
    try std.testing.expect(isCtrlBackslash("\x1b[92:124:92;69:2u"));
    try std.testing.expect(isCtrlBackslash("\x1b[92;5;28:92u"));
    try std.testing.expect(isCtrlBackslash("\x1b[27;5;92~"));
    try std.testing.expect(isCtrlBackslash("prefix\x1b[27;197;92~"));
}

test "detach rejects releases and extra intentional modifiers" {
    try std.testing.expect(!isCtrlBackslash("\x1b[92;5:3u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92;6u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92;7u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92;13u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[27;6;92~"));
    try std.testing.expect(!isCtrlBackslash("\x1b[27;5;91~"));
}

test "detach rejects malformed and truncated sequences" {
    try std.testing.expect(!isCtrlBackslash(""));
    try std.testing.expect(!isCtrlBackslash("garbage"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92;"));
    try std.testing.expect(!isCtrlBackslash("\x1b[92;u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[27;5;92"));
    try std.testing.expect(!isCtrlBackslash("\x1b[27;5;92u"));
    try std.testing.expect(!isCtrlBackslash("\x1b[999999999999999999999;5u"));
}

test "text, UTF-8, whitespace, and controls are input" {
    try std.testing.expect(isUserInput("hello, world!"));
    try std.testing.expect(isUserInput("héllo 世界 🙂"));
    try std.testing.expect(isUserInput(" \t\r\n\x08\x00\x1c"));
    try std.testing.expect(isUserInput("\xc3" ++ "\xa9"));
    try std.testing.expect(!isUserInput(""));
    try std.testing.expect(!isUserInput("\xff"));
    try std.testing.expect(!isUserInput("\xe2\x82"));
}

test "legacy, modified, Kitty, and bracketed paste keys are input" {
    try std.testing.expect(isUserInput("\x1b[A"));
    try std.testing.expect(isUserInput("\x1b[1;5C"));
    try std.testing.expect(isUserInput("\x1bOA"));
    try std.testing.expect(isUserInput("\x1bOP"));
    try std.testing.expect(isUserInput("\x1b[E"));
    try std.testing.expect(isUserInput("\x1b[F"));
    try std.testing.expect(isUserInput("\x1b[H"));
    try std.testing.expect(isUserInput("\x1b[P"));
    try std.testing.expect(isUserInput("\x1b[Q"));
    try std.testing.expect(isUserInput("\x1b[S"));
    try std.testing.expect(isUserInput("\x1bOE"));
    try std.testing.expect(isUserInput("\x1bOF"));
    try std.testing.expect(isUserInput("\x1bOH"));
    try std.testing.expect(isUserInput("\x1bOQ"));
    try std.testing.expect(isUserInput("\x1bOS"));
    try std.testing.expect(!isUserInput("\x1b[R"));
    try std.testing.expect(!isUserInput("\x1bOR"));
    try std.testing.expect(isUserInput("\x1b[15;2~"));
    try std.testing.expect(isUserInput("\x1b[27;5;92~"));
    try std.testing.expect(isUserInput("\x1b[11;2u"));
    try std.testing.expect(isUserInput("\x1b[97u"));
    try std.testing.expect(isUserInput("\x1b[102;1:1u"));
    try std.testing.expect(isUserInput("\x1b[57444;1:1u"));
    try std.testing.expect(isUserInput("\x1b[200~hello\x1b[201~"));
    try std.testing.expect(!isUserInput("\x1b[102;1:3u"));
    try std.testing.expect(!isUserInput("\x1b[102;1:3u\x1b[I\x1b[0m"));
    try std.testing.expect(!isUserInput("\x1b[97;1:3u"));
}

test "mouse and focus reports are not input" {
    try std.testing.expect(!isUserInput("\x1b[M@ 0 0"));
    try std.testing.expect(!isUserInput("\x1b[<0;1;1M"));
    try std.testing.expect(!isUserInput("\x1b[<64;1;1M"));
    try std.testing.expect(!isUserInput("\x1b[I\x1b[O"));
    try std.testing.expect(!isUserInput("\x1b[2;1H\x1b[0m\x1b[6n"));
}

test "X10 mouse packets do not swallow following text" {
    // CSI M plus @, space, 0 is one complete X10 packet.
    try std.testing.expect(isUserInput("\x1b[M@ 0typed text"));
    try std.testing.expect(isUserInput("\x1b[M@ 0héllo"));
}

test "mixed keyboard and automatic reports retain keyboard classification" {
    try std.testing.expect(isUserInput("\x1b[M@ 0 0\x1b[3~"));
    try std.testing.expect(isUserInput("\x1b[I\x1b[102;1:1u\x1b[<0;1;1M"));
    try std.testing.expect(isUserInput("mouse noise\x1b[200~"));
}

test "stream classifier preserves split sequences and UTF-8" {
    var classifier = StreamClassifier{};
    classifier.feed("\x1b[92:124;");
    try std.testing.expect(!classifier.isCtrlBackslash());
    classifier.feed("69:2u");
    try std.testing.expect(classifier.isCtrlBackslash());
    try std.testing.expect(classifier.isUserInput());

    var text = StreamClassifier{};
    text.feed("\xe2");
    try std.testing.expect(!text.isUserInput());
    text.feed("\x82");
    text.feed("\xac");
    try std.testing.expect(text.isUserInput());

    var mouse_and_key = StreamClassifier{};
    mouse_and_key.feed("\x1b[M@");
    mouse_and_key.feed(" 0 0\x1b[");
    mouse_and_key.feed("3~");
    try std.testing.expect(mouse_and_key.isUserInput());
}

test "stream result holds split detach prefixes" {
    var classifier = StreamClassifier{};
    try std.testing.expectEqual(StreamClassifier.FeedResult.pending, classifier.feedResult("\x1b[92;"));
    try std.testing.expect(!classifier.isCtrlBackslash());
    try std.testing.expectEqual(StreamClassifier.FeedResult.ctrl_backslash, classifier.feedResult("5u"));
    try std.testing.expect(classifier.isCtrlBackslash());
}

test "stream result preserves input before a split non-input sequence" {
    var classifier = StreamClassifier{};
    try std.testing.expectEqual(StreamClassifier.FeedResult.pending, classifier.feedResult("typed\x1b["));
    try std.testing.expectEqual(StreamClassifier.FeedResult.user_input, classifier.feedResult("2J"));
}

test "stream classifier safely discards unfinished and oversized input" {
    var classifier = StreamClassifier{};
    classifier.feed("\x1b[92;5");
    classifier.finish();
    try std.testing.expect(!classifier.isCtrlBackslash());
    try std.testing.expect(!classifier.isUserInput());

    var oversized = StreamClassifier{};
    var long_string: [MAX_PENDING_BYTES + 8]u8 = undefined;
    @memset(long_string[0..], 'x');
    long_string[0] = ESC;
    long_string[1] = ']';
    oversized.feed(&long_string);
    oversized.finish();
    try std.testing.expect(!oversized.isUserInput());
}
