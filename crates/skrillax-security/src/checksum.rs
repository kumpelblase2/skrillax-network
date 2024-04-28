use std::sync::OnceLock;

const BASE_TABLE: [u32; 256] = [
    0x968BD6B1, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B17148, 0x8CBE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8B7A50F,
    0x2802B89E, 0x5F058808, 0xC6ECD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0FA0F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x63B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C908, 0xB0D09822, 0xC757A8B4, 0x59B33D17, 0x3EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A2D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x46690E79,
    0xCB51B38C, 0xBC63831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220214B9, 0x5505262F,
    0xC5B63BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B6472B0, 0xECE3F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076885, 0x05000713,
    0x95BF4882, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D294, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE0, 0xF10F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF91C, 0xCABACD8A, 0x53B39E30, 0x24BCA3A6, 0xBAD03B05, 0xCDD706A3, 0x54DE57E9, 0x23D967BF,
    0xB366722E, 0xC4614AB8, 0x5D381B02, 0x2B6F2B94, 0xB4CBBE37, 0xC3CC8EA1, 0x5A0DDF1B, 0x2D02ED8D,
];

fn generate_table() -> [u32; 256 * 256] {
    let mut final_table = [0u32; 256 * 256];
    let mut current_index = 0;

    for edx in &BASE_TABLE {
        for ecx in 0..256 {
            let mut eax = ecx >> 1;
            if (ecx & 1) != 0 {
                eax ^= edx;
            }

            for _ in 0..7 {
                if eax & 1 != 0 {
                    eax >>= 1;
                    eax ^= edx;
                } else {
                    eax >>= 1;
                }
            }

            final_table[current_index] = eax;
            current_index += 1;
        }
    }

    final_table
}

static EXPANDED_TABLE: OnceLock<[u32; 256 * 256]> = OnceLock::new();

/// Generates a CRC checksum according to the algorithm used in Silkroad Online.
///
/// Just like a hash, given the same input (seed & data), it will produce the same output. The seed
/// is expected to be generated randomly and exchanged prior. Then the output can be used to ensure
/// no accidental changes have been made to the data.
///
/// ```
/// # use rand::random;
/// # use skrillax_security::Checksum;
/// let checksum = Checksum::new(random::<u32>());
/// let crc = checksum.generate_byte(&[0x01, 0x02]);
/// ```
///
/// While the `seed` is considered a `u32`, only the lower 8 bits are actually used; any other will
/// be discarded. Technically, it would be more correct for this seed to accept a `u8` instead to
/// ensure this on a type level. However, we're keeping it as a `u32` because inside the silkroad
/// packets the seed occupies a `u32`. We want to keep this in sync. For now, the following is thus
/// correct:
/// ```
/// # use skrillax_security::Checksum;
/// let checksum = Checksum::new(10 + 256);
/// let checksum2 = Checksum::new(10);
/// assert_eq!(checksum, checksum2);
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Checksum {
    seed: u32,
}

impl Checksum {
    /// Creates a new checksum from a given seed.
    pub fn new(seed: u32) -> Self {
        Self {
            seed: (seed & 0xFF) << 8,
        }
    }

    /// Generates the CRC byte for the given buffer.
    pub fn generate_byte(&self, buffer: &[u8]) -> u8 {
        self.builder().update(buffer).digest()
    }

    /// Creates a [ChecksumBuilder] for a more fluent api.
    pub fn builder(&self) -> ChecksumBuilder {
        ChecksumBuilder::new(self.seed)
    }
}

/// A builder to update the digest of the checksum incrementally.
///
/// Sometimes we don't have a continuous buffer for creating a checksum, so calling
/// [Checksum::generate_byte] would require us to allocate a completely new buffer. Since we're not
/// actually storing much data for calculating the checksum, it might be better to instead build up
/// the checksum in individual steps.
///
/// ```
/// # use skrillax_security::Checksum;
/// let checksum = Checksum::new(0);
/// let mut builder = checksum.builder();
/// let crc = builder.update(&[0x01, 0x01]).update_byte(1).update(&[0x05]).digest();
/// ```
pub struct ChecksumBuilder<'a> {
    seed: u32,
    current_checksum: u32,
    table: &'a [u32; 256 * 256],
}

impl<'a> ChecksumBuilder<'a> {
    fn new(seed: u32) -> ChecksumBuilder<'a> {
        Self {
            seed,
            current_checksum: 0xFFFFFFFF,
            table: EXPANDED_TABLE.get_or_init(generate_table),
        }
    }

    /// Updates the internal state by adding a single byte.
    pub fn update_byte(&mut self, value: u8) -> &mut Self {
        let index = self.seed + ((value as u32 ^ self.current_checksum) & 0xFF);
        self.current_checksum = (self.current_checksum >> 8) ^ self.table[index as usize];
        self
    }

    /// Updates the internal state by adding each byte of the buffer.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        for value in data {
            self.update_byte(*value);
        }
        self
    }

    /// Creates the CRC byte for the currently ingested bytes.
    pub fn digest(&self) -> u8 {
        ((self.current_checksum >> 24 & 0xFF)
            + (self.current_checksum >> 16 & 0xFF)
            + (self.current_checksum >> 8 & 0xFF)
            + (self.current_checksum & 0xFF)) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_with_known_value() {
        let checksum = Checksum::new(42);
        let data = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

        assert_eq!(checksum.generate_byte(data), 54);
    }

    #[test]
    fn compare_with_sniffed() {
        let checksum = Checksum::new(0x61);
        let data = &[
            0x0c, 0x00, 0x00, 0x50, 0xb7, 0x00, 0x7b, 0x8e, 0xdd, 0x13, 0x6e, 0x8b, 0x1a, 0x3d,
            0x66, 0x31, 0xa7, 0xcd,
        ];
        assert_eq!(checksum.generate_byte(data), 0xf1);
    }
}
