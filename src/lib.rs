//! See [hashverify.c](https://gitlab.com/fwojcik/smhasher3/-/blob/34093a3a849cae8ae1293975b004a740d2372fd7/misc/hashverify.c) for reference.

const MESSAGE: [u8; 255] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
];

/// Computes hash verification code that used in SMHasher.
///
/// - `result_bits`: The output width of the hash in bits.
/// - `hash`: Function `hash(bytes: &[u8], seed: u64, out: &mut [u8])`.
///
/// # Panics
///
/// Panics if `result_bits` is less than 32 or not a multiple of 8.
pub fn compute(result_bits: usize, hash: impl Fn(&[u8], u64, &mut [u8])) -> u32 {
    assert!(result_bits >= 32 && result_bits % 8 == 0);

    let result_bytes = result_bits / 8;
    let mut outs = vec![0u8; result_bytes * 256];
    let mut out1 = vec![0u8; result_bytes];

    for i in 0..256 {
        hash(
            &MESSAGE[0..i],
            256 - i as u64,
            &mut outs[result_bytes * i..][..result_bytes],
        );
    }

    hash(&outs, 0, &mut out1);

    u32::from_le_bytes(*out1.first_chunk().unwrap())
}

const MESSAGE3: [u8; 1024] = {
    let mut msg = [0x00; 1024];
    let mut i = 0;
    let mut x = 0;

    while i < 512 {
        x += i;

        let v = ((x ^ x << 8) >> 1) as u16;
        msg[i * 2] = v as u8;
        msg[i * 2 + 1] = (v >> 8) as u8;

        i += 1;
    }

    msg
};

pub fn compute_v3(result_bits: usize, hash: impl Fn(&[u8], u64, &mut [u8])) -> u64 {
    assert!(result_bits % 8 == 0);

    const SEED: u64 = 0x123456789abcdef;
    const SIZE: usize = 1025 * 1024 / 2;

    let result_bytes = result_bits / 8;
    let mut outs = vec![0u8; result_bytes * (SIZE + 1)];
    let mut out1 = vec![0u8; result_bytes.max(8)];

    let mut x = 0;
    let mut seed = SEED;
    for i in 1..=1024 {
        for (j, msg) in MESSAGE3.windows(1025 - i).enumerate() {
            hash(
                msg,
                seed,
                &mut outs[result_bytes * (x + j)..][..result_bytes],
            )
        }

        x += i;

        seed = seed.wrapping_mul(SEED);
        seed ^= seed >> 32;
    }

    hash(&[], seed, &mut outs[result_bytes * SIZE..]);

    hash(&outs, seed, &mut out1[..result_bytes]);

    u64::from_le_bytes(*out1.first_chunk().unwrap())
}

#[cfg(test)]
mod tests_v3 {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32c() {
        println!(
            "0x{:016x}", // 0x00000000037f6825
            compute_v3(32, |bytes, seed, out| out.copy_from_slice(
                &crc32c::crc32c_append(seed as u32, bytes).to_le_bytes()
            ))
        );
    }

    #[test]
    fn siphash() {
        println!(
            "0x{:016x}", // 0x4134c87fb072a700
            compute_v3(64, |bytes, seed, out| {
                out.copy_from_slice(
                    &siphasher::sip::SipHasher13::new_with_keys(seed, 0)
                        .hash(bytes)
                        .to_le_bytes(),
                )
            })
        );
        println!(
            "0x{:016x}", // 0x36f8448d51184978
            compute_v3(64, |bytes, seed, out| {
                out.copy_from_slice(
                    &siphasher::sip::SipHasher24::new_with_keys(seed, 0)
                        .hash(bytes)
                        .to_le_bytes(),
                )
            })
        );
    }

    #[test]
    fn murmurhash3() {
        println!(
            "0x{:016x}", // 0x0000000035362482
            compute_v3(32, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_32(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
        println!(
            "0x{:016x}", // 0x9af56cabce962df8
            compute_v3(128, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_x86_128(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
        println!(
            "0x{:016x}", // 0x6f2fd17887f1b7e1
            compute_v3(128, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_x64_128(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
    }

    #[test]
    fn msg3_bit_weights() {
        let bw = MESSAGE3.iter().copied().map(u8::count_ones).sum::<u32>();

        println!("{}", bw);
    }
}

/// These verification codes can be found at
/// <https://gitlab.com/fwojcik/smhasher3/-/blob/34093a3a849cae8ae1293975b004a740d2372fd7/hashes>.
#[cfg(test)]
mod stability_v1 {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32c() {
        assert_eq!(
            0x6E6071BD, /* crc.cpp#L405 */
            compute(32, |bytes, seed, out| out.copy_from_slice(
                &crc32c::crc32c_append(seed as u32, bytes).to_le_bytes()
            ))
        );
    }

    #[test]
    fn siphash() {
        assert_eq!(
            0x8936B193, /* siphash.cpp#L453 */
            compute(64, |bytes, seed, out| out.copy_from_slice(
                &siphasher::sip::SipHasher13::new_with_keys(seed, 0)
                    .hash(bytes)
                    .to_le_bytes()
            ))
        );
        assert_eq!(
            0x57B661ED, /* siphash.cpp#L453 */
            compute(64, |bytes, seed, out| out.copy_from_slice(
                &siphasher::sip::SipHasher24::new_with_keys(seed, 0)
                    .hash(bytes)
                    .to_le_bytes()
            ))
        );
    }

    #[test]
    fn murmurhash3() {
        assert_eq!(
            0xB0F57EE3, /* murmurhash3.cpp#L312 */
            compute(32, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_32(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
        assert_eq!(
            0xB3ECE62A, /* murmurhash3.cpp#L329 */
            compute(128, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_x86_128(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
        assert_eq!(
            0x6384BA69, /* murmurhash3.cpp#L346 */
            compute(128, |bytes, seed, out| out.copy_from_slice(
                &murmur3::murmur3_x64_128(&mut Cursor::new(bytes), seed as u32)
                    .unwrap()
                    .to_le_bytes()
            ))
        );
    }
}
