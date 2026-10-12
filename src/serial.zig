const std = @import("std");

fn mask(bits: u7) u64 {
    if (bits == 0) return 0;
    if (bits >= 64) return std.math.maxInt(u64);
    return (@as(u64, 1) << @intCast(bits)) - 1;
}

// A simple keyed mixing function.
// This is illustrative, not a cryptographic PRF.
fn roundFunction(x: u64, key: u64, round: u64) u64 {
    var z = x ^ key ^ (round *% 0x9E3779B97F4A7C15);

    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    z ^= z >> 31;

    return z;
}

// Permute an n-bit value, where 1 <= bits <= 64.
fn feistel(
    input: u64,
    bits: u7,
    key: u64,
    rounds: u32,
) u64 {
    std.debug.assert(bits >= 1 and bits <= 64);
    std.debug.assert(input & ~mask(bits) == 0);

    // A one-bit domain is handled separately.
    if (bits == 1) return input;

    // Unequal halves are allowed.
    var left_bits: u7 = bits / 2;
    var right_bits: u7 = bits - left_bits;

    var left = (input >> @intCast(right_bits)) & mask(left_bits);
    var right = input & mask(right_bits);

    for (0..rounds) |r| {
        const next_left = right;
        const next_right =
            left ^ (roundFunction(right, key, r) & mask(left_bits));

        left = next_left;
        right = next_right;

        const old_left_bits = left_bits;
        left_bits = right_bits;
        right_bits = old_left_bits;
    }

    // Pack the halves using their current widths.
    return ((left & mask(left_bits)) << @intCast(right_bits))
        | (right & mask(right_bits));
}

// Uses the Feistel function to generate a unique and complete serial number with the required amount of digits
// Because the Feistel function is bijective, we guarantee that we won't miss any value
// Because the round function constants are fixed and the key size is small (64-bits), this should not be used
// as a cryptographically secure mapping
// The input number should be smaller than the the number of digits you require (e.g. 234 does not fit in 2 or 1 digit but will fit in 3,4,5.... digits)
// The maximum number of digits is 19 because more won't fit in 64-bit numbers
pub fn generate_serial(input_number: u64, digits: u5, key: u64) !u64 {
    // Only 19 digits fit in a u64
    if (digits > 19) {
        return error.TooManyDigits;
    }

    var required_digits = std.math.log(f64, 10, @floatFromInt(input_number));

    const ceiled = @ceil(required_digits);
    if (required_digits == ceiled) {
        required_digits = ceiled + 1;
    } else {
        required_digits = ceiled;
    }

    if (required_digits > digits) {
        return error.InputOutOfBounds;
    }
    
    const digits_size = std.math.pow(f64, 10.0, @floatFromInt(digits));
    const digits_size_int: u64 = @intFromFloat(digits_size);

    var required_bits: u7 = @intFromFloat(@ceil(std.math.log(f64, 2, digits_size)));
    if (required_bits % 2 != 0) {
        required_bits += 1;
    }

    var result: u64 = input_number;
    while (true) {
        result = feistel(result, required_bits, key, 8);
        if (result < digits_size_int) {
            break;
        }
    }

    return result;
}

test "generate 1 digit serial" {
    // The expected values cover all 1-digit numbers
    try std.testing.expectEqual(6, try generate_serial(0, 1, 1));
    try std.testing.expectEqual(4,try generate_serial(1, 1, 1));
    try std.testing.expectEqual(9,try generate_serial(2, 1, 1));
    try std.testing.expectEqual(3,try generate_serial(3, 1, 1));
    try std.testing.expectEqual(0,try generate_serial(4, 1, 1));
    try std.testing.expectEqual(1,try generate_serial(5, 1, 1));
    try std.testing.expectEqual(2,try generate_serial(6, 1, 1));
    try std.testing.expectEqual(8,try generate_serial(7, 1, 1));
    try std.testing.expectEqual(7,try generate_serial(8, 1, 1));
    try std.testing.expectEqual(5,try generate_serial(9, 1, 1));
}

test "Feistel permutation stays in domain and is bijective" {
    const bits: u7 = 7;
    const key: u64 = 0x123456789ABCDEF0;
    const domain_size = @as(u64, 1) << @intCast(bits);

    var seen: [128]bool = @splat(false);

    for (0..domain_size) |i| {
        const y = feistel(i, bits, key, 8);

        try std.testing.expect(y < domain_size);
        try std.testing.expect(!seen[@intCast(y)]);

        seen[@intCast(y)] = true;
    }
}
