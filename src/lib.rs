//! See [hashverify.c](https://gitlab.com/fwojcik/smhasher3/-/blob/34093a3a849cae8ae1293975b004a740d2372fd7/misc/hashverify.c) for reference.

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

    const VECT: [u8; 255] = {
        let mut buf = [0x00; 255];
        let mut i = 0;

        while i < 255 {
            buf[i] = i as u8;
            i += 1;
        }

        buf
    };

    let result_bytes = result_bits / 8;
    let mut outs = vec![0u8; result_bytes * 256];
    let mut out1 = vec![0u8; result_bytes];

    for i in 0..256 {
        hash(
            &VECT[..i],
            256 - i as u64,
            &mut outs[result_bytes * i..][..result_bytes],
        );
    }

    hash(&outs, 0, &mut out1);

    u32::from_le_bytes(*out1.first_chunk().unwrap())
}

pub fn compute_v3(result_bits: usize, hash: impl Fn(&[u8], u64, &mut [u8])) -> u64 {
    assert!(result_bits % 8 == 0);

    const SEED: u64 = 0x123456789abcdef;
    const SIZE: usize = 1025 * 1024 / 2;
    const VECT: [u8; 1024] = {
        let mut buf = [0x00; 1024];
        let mut i = 0;
        let mut x = 0;

        while i < 512 {
            x += i;

            let v = ((x ^ x << 8) >> 1) as u16;
            buf[i * 2] = v as u8;
            buf[i * 2 + 1] = (v >> 8) as u8;

            i += 1;
        }

        buf
    };

    let result_bytes = result_bits / 8;
    let mut outs = vec![0u8; result_bytes * (SIZE + 1)];
    let mut out1 = vec![0u8; result_bytes.max(8)];

    let mut x = 0;
    let mut seed = SEED;
    for i in 1..=1024 {
        for (j, key) in VECT.windows(1025 - i).enumerate() {
            hash(
                key,
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
