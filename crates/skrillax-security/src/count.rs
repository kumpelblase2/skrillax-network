use std::cmp::max;

fn generate_value(mut value: u32) -> u32 {
    for _ in 0..32 {
        let mut v = value;
        v = (v >> 2) ^ value;
        v = (v >> 2) ^ value;
        v = (v >> 1) ^ value;
        v = (v >> 1) ^ value;
        v = (v >> 1) ^ value;
        value = (((value >> 1) | (value << 31)) & (!1)) | (v & 1);
    }
    value
}

/// A cryptographic counter for verifying message order.
///
/// To verify that messages arrive in the correct order and aren't reused at a
/// later time, you can use a cryptographic counter. It is essentially a PRNG
/// that always returns a single byte. Similarly to a PRNG, we need to provide a
/// seed before we can generate values.
///
/// ```
/// # use rand::random;
/// # use skrillax_security::MessageCounter;
/// let mut counter = MessageCounter::new(random::<u32>());
/// let first = counter.next_byte();
/// let second = counter.next_byte();
/// ```
pub struct MessageCounter {
    seeds: [u8; 3],
}

impl MessageCounter {
    /// Creates a new counter with the given seed.
    pub fn new(seed: u32) -> MessageCounter {
        let mut1 = generate_value(seed);
        let mut2 = generate_value(mut1);
        let mut3 = generate_value(mut2);
        let mut4 = generate_value(mut3);

        let byte1 = (mut1 as u8) ^ (mut2 as u8);
        let byte1 = max(byte1, 1);

        let byte2 = (mut3 as u8) ^ (mut4 as u8);
        let byte2 = max(byte2, 1);

        MessageCounter {
            seeds: [byte1 ^ byte2, byte1, byte2],
        }
    }

    /// Generates the next byte of the counter.
    ///
    /// Generates the next byte by advancing the internal state according to the
    /// generation algorithm.
    pub fn next_byte(&mut self) -> u8 {
        let value = (self.seeds[2] as u32 * (!self.seeds[0] as u32 + self.seeds[1] as u32)) as u8;
        self.seeds[0] = value ^ value >> 4;

        self.seeds[0]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sniffed() {
        let mut counter = MessageCounter::new(0x7c);
        assert_eq!(counter.next_byte(), 0xb7);
    }
}
