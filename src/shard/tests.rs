use super::*;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Deterministic test bytes (SplitMix64).
fn bytes(seed: u64, count: usize) -> Vec<u8> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            (z ^ (z >> 31)) as u8
        })
        .collect()
}

fn data(k: usize, length: usize, seed: u64) -> Vec<Vec<u8>> {
    (0..k).map(|i| bytes(seed + i as u64, length)).collect()
}

fn pieces(code: &Code, data: &[Vec<u8>], n: usize) -> Vec<Vec<u8>> {
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    (0..n).map(|i| code.piece(&refs, i).unwrap()).collect()
}

#[test]
fn the_field_has_its_known_products_and_inverses() {
    // 2 · 0x80 = x^8 = x^4 + x^3 + x^2 + 1 = 0x1D under 0x11D.
    assert_eq!(field::multiply(2, 0x80), 0x1D);
    for a in 1..=255_u8 {
        let inverse = field_inverse(a).unwrap();
        assert_eq!(field::multiply(a, inverse), 1, "a {a}");
    }
    assert_eq!(field_inverse(0), None);
}

#[test]
fn four_one_byte_pieces_give_the_published_parity() {
    // 01 02 03 04 with two parity pieces: 45 5E, the parity of reed-solomon-erasure 6.0.0 and of
    // klauspost's Go code for the same shape.
    let code = Code::new(4).unwrap();
    let data: [&[u8]; 4] = [&[1], &[2], &[3], &[4]];
    assert_eq!(code.piece(&data, 4).unwrap(), [0x45]);
    assert_eq!(code.piece(&data, 5).unwrap(), [0x5E]);
}

#[test]
fn parity_equals_reed_solomon_erasure_for_every_shape_up_to_16() {
    for n in 2..=16 {
        for k in 1..n {
            let length = 1 + (n * 7 + k) % 70;
            let data = data(k, length, (n * 100 + k) as u64);
            let ours = pieces(&Code::new(k).unwrap(), &data, n);
            let mut theirs: Vec<Vec<u8>> = data.clone();
            theirs.extend((k..n).map(|_| vec![0; length]));
            ReedSolomon::new(k, n - k)
                .unwrap()
                .encode(&mut theirs)
                .unwrap();
            assert_eq!(ours, theirs, "k {k} n {n}");
        }
    }
}

#[test]
fn every_choice_of_k_pieces_rebuilds_the_data() {
    for (k, n) in [(1, 3), (2, 3), (3, 5), (4, 7), (5, 10), (8, 16)] {
        let code = Code::new(k).unwrap();
        let data = data(k, 5, (k * 31 + n) as u64);
        let all = pieces(&code, &data, n);
        for mask in 0_u32..1 << n {
            if mask.count_ones() as usize != k {
                continue;
            }
            let chosen: Vec<(usize, &[u8])> = (0..n)
                .filter(|i| mask >> i & 1 == 1)
                .map(|i| (i, all[i].as_slice()))
                .collect();
            assert_eq!(
                code.rebuild(&chosen).unwrap(),
                data,
                "k {k} n {n} mask {mask:b}"
            );
        }
    }
}

#[test]
fn a_lost_piece_is_made_again_and_a_set_grows_without_touching_its_pieces() {
    let code = Code::new(3).unwrap();
    let data = data(3, 33, 7);
    let first_five = pieces(&code, &data, 5);
    // Piece 2 is lost: pieces 0, 3 and 4 make it again.
    let rest: Vec<(usize, &[u8])> = [0, 3, 4]
        .iter()
        .map(|&i| (i, first_five[i].as_slice()))
        .collect();
    let rebuilt = code.rebuild(&rest).unwrap();
    let refs: Vec<&[u8]> = rebuilt.iter().map(Vec::as_slice).collect();
    assert_eq!(code.piece(&refs, 2).unwrap(), first_five[2]);
    // The set grows to seven: the first five stay as they were.
    let seven = pieces(&code, &data, 7);
    assert_eq!(&seven[..5], &first_five[..]);
    let mixed: Vec<(usize, &[u8])> = [6, 1, 5]
        .iter()
        .map(|&i| (i, seven[i].as_slice()))
        .collect();
    assert_eq!(code.rebuild(&mixed).unwrap(), data);
}

#[test]
fn a_changed_piece_breaks_the_consistency_of_a_set() {
    let code = Code::new(2).unwrap();
    let all = pieces(&code, &data(2, 9, 3), 4);
    let mut set: Vec<(usize, Vec<u8>)> = all.iter().cloned().enumerate().collect();
    let view = |set: &[(usize, Vec<u8>)]| -> Vec<(usize, Vec<u8>)> { set.to_vec() };
    let refs = |set: &[(usize, Vec<u8>)]| -> bool {
        let pairs: Vec<(usize, &[u8])> = set.iter().map(|(i, p)| (*i, p.as_slice())).collect();
        code.consistent(&pairs).unwrap()
    };
    assert!(refs(&view(&set)));
    set[3].1[4] ^= 1;
    assert!(!refs(&set));
}

#[test]
fn wrong_shapes_and_pieces_are_refused() {
    assert_eq!(Code::new(0).err(), Some(ShardError::Shape));
    let code = Code::new(3).unwrap();
    let a = [1_u8, 2];
    let b = [3_u8];
    assert_eq!(code.piece(&[&a, &a, &b], 3), Err(ShardError::Pieces));
    assert_eq!(code.rebuild(&[(0, &a), (1, &a)]), Err(ShardError::TooFew));
    assert_eq!(
        code.rebuild(&[(0, &a), (0, &a), (1, &a)]),
        Err(ShardError::Pieces)
    );
    assert_eq!(
        code.rebuild(&[(0, &a), (1, &a), (256, &a)]),
        Err(ShardError::Pieces)
    );
}
