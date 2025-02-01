const std = @import("std");

const Base64 = struct {
    _table: *const [64]u8,

    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const numbers_symb = "0123456789+/";

        return Base64{ ._table = upper ++ lower ++ numbers_symb };
    }

    fn _char_at(self: Base64, index: u8) u8 {
        return self._table[index];
    }

    // This is not efficient, but it works
    // we could use a hash table
    // or use a binary search
    fn _char_index(self: Base64, char: u8) u8 {
        if (char == '=') {
            return 64;
        }

        var index: u8 = 0;

        while (index < 64) {
            if (self._table[index] == char) {
                return index;
            }
            index += 1;
        }
        unreachable;
    }

    fn decode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }
        const n_output = try _calc_decode_len(input);
        var output = try allocator.alloc(u8, n_output);
        var count: u8 = 0;
        var iout: u64 = 0;
        var buf = [4]u8{ 0, 0, 0, 0 };

        for (0..input.len) |i| {
            buf[count] = self._char_index(input[i]);
            count += 1;
            if (count == 4) {
                output[iout] = (buf[0] << 2) + (buf[1] >> 4);
                if (buf[2] != 64) {
                    output[iout + 1] = (buf[1] << 4) + (buf[2] >> 2);
                }
                if (buf[3] != 64) {
                    output[iout + 2] = (buf[2] << 6) + buf[3];
                }
                iout += 3;
                count = 0;
            }
        }

        return output;
    }

    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const n_out = try _calc_encode_len(input);
        var out = try allocator.alloc(u8, n_out);
        var buf = [3]u8{ 0, 0, 0 };
        var count: u8 = 0;
        var iout: u64 = 0;

        for (input) |byte| {
            buf[count] = byte;
            count += 1;

            // process 3 bytes
            if (count == 3) {
                // Encode the first 6 bits of buf[0]
                out[iout] = self._char_at(buf[0] >> 2);
                // Encode the last 2 bits of buf[0] and the first 4 bits of buf[1]
                // 0x03 -> 0b00000011
                out[iout + 1] = self._char_at(((buf[0] & 0x03) << 4) + (buf[1] >> 4));
                // Encode the last 4 bits of buf[1] and the first 2 bits of buf[2]
                // 0x0f -> 0b00001111
                out[iout + 2] = self._char_at(((buf[1] & 0x0f) << 2) + (buf[2] >> 6));
                // Encode the last 6 bits of buf[2]
                // 0x3f -> 0b00111111
                out[iout + 3] = self._char_at(buf[2] & 0x3f);
                iout += 4;
                count = 0;
            }
        }
        if (count > 0) {
            // Encode the first 6 bits of buf[0]
            out[iout] = self._char_at(buf[0] >> 2);

            if (count == 1) {
                // Encode the last 2 bits of buf[0] and pad with '='
                out[iout + 1] = self._char_at((buf[0] & 0x03) << 4);
                out[iout + 2] = '=';
                out[iout + 3] = '=';
            } else if (count == 2) {
                // Encode the last 2 bits of buf[0] and the first 4 bits of buf[1]
                out[iout + 1] = self._char_at(((buf[0] & 0x03) << 4) + (buf[1] >> 4));
                // Encode the last 4 bits of buf[1] and pad with '='
                out[iout + 2] = self._char_at((buf[1] & 0x0f) << 2);
                out[iout + 3] = '=';
            }
        }

        return out;
    }
};

fn _calc_encode_len(input: []const u8) !usize {
    if (input.len < 3) {
        return 4;
    }

    const n_output = try std.math.divCeil(usize, input.len, 3);

    return n_output * 4;
}

fn _calc_decode_len(input: []const u8) !usize {
    var padding: usize = 0;
    if (input.len >= 1 and input[input.len - 1] == '=') {
        padding += 1;
    }
    if (input.len >= 2 and input[input.len - 2] == '=') {
        padding += 1;
    }
    return (input.len / 4) * 3 - padding;
}

pub fn main() !void {}

test "base64._char_at" {
    const base64 = Base64.init();
    try std.testing.expectEqual(base64._char_at(0), 'A');
    try std.testing.expectEqual(base64._char_at(25), 'Z');
    try std.testing.expectEqual(base64._char_at(26), 'a');
    try std.testing.expectEqual(base64._char_at(51), 'z');
    try std.testing.expectEqual(base64._char_at(52), '0');
    try std.testing.expectEqual(base64._char_at(62), '+');
    try std.testing.expectEqual(base64._char_at(63), '/');
}

test "base64._char_index" {
    const base64 = Base64.init();
    try std.testing.expectEqual(base64._char_index('A'), 0);
    try std.testing.expectEqual(base64._char_index('Z'), 25);
    try std.testing.expectEqual(base64._char_index('a'), 26);
    try std.testing.expectEqual(base64._char_index('z'), 51);
    try std.testing.expectEqual(base64._char_index('0'), 52);
    try std.testing.expectEqual(base64._char_index('+'), 62);
    try std.testing.expectEqual(base64._char_index('='), 64);
}

test "base64.encode" {
    const base64 = Base64.init();
    const input = "hello world";
    const output = try base64.encode(std.testing.allocator, input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualSlices(u8, output, "aGVsbG8gd29ybGQ=");

    const input2 = "0";
    const output2 = try base64.encode(std.testing.allocator, input2);
    defer std.testing.allocator.free(output2);
    try std.testing.expectEqualSlices(u8, output2, "MA==");
}

test "base64.decode" {
    const base64 = Base64.init();
    const input = "aGVsbG8gd29ybGQ=";
    const output = try base64.decode(std.testing.allocator, input);
    defer std.testing.allocator.free(output);
    try std.testing.expectEqualSlices(u8, output, "hello world");
}

test "_calc_encode_len" {
    try std.testing.expectEqual(try _calc_encode_len(""), 4);
    try std.testing.expectEqual(try _calc_encode_len("ab"), 4);
    try std.testing.expectEqual(try _calc_encode_len("abc"), 4);
    try std.testing.expectEqual(try _calc_encode_len("abcd"), 8);
}

test "_calc_decode_len" {
    try std.testing.expectEqual(try _calc_decode_len(""), 0);
    try std.testing.expectEqual(try _calc_decode_len("aa"), 0);
    try std.testing.expectEqual(try _calc_decode_len("aaa"), 0);
    try std.testing.expectEqual(try _calc_decode_len("aaaaaaaa"), 6);
}
