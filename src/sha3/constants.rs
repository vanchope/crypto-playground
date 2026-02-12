

// see Table 2 on p.13; Offsets of Rho algorithm
pub const RHO_OFFSETS: [[i32; 5] ;5] = [ // [x][y]
    [0, 36, 3, 105, 210],
    [1, 300, 10, 45, 66],
    [190, 6, 171, 15, 253],
    [28, 55, 153, 21, 120],
    [91, 276, 231, 136, 78]
];


/// Table 1 of speca, which defines a list of of tuples (el, w, b).
pub const KECCAK_CONSTANTS: [[usize;3];7] = [
    [0, 1, 25],
    [1, 2, 50],
    [2, 4, 100],
    [3, 8, 200],
    [4, 16, 400],
    [5, 32, 800],
    [6, 64, 1600],
];

pub const KECCAK_B: usize = 1600;

pub const KECCAK_NR: usize = 24;

pub fn get_w_from_b(b: usize) -> usize {
    for tuple in KECCAK_CONSTANTS {
        if b==tuple[2] {
            return tuple[1];
        }
    }
    panic!()
}

pub fn get_el_from_b(b: usize) -> usize {
    for tuple in KECCAK_CONSTANTS {
        if b==tuple[2] {
            return tuple[0];
        }
    }
    panic!()
}