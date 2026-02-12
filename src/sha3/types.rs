pub enum Sha3Variant {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

/// each element x is (0 <= x <= 255)
pub type ByteString = Vec<u8>;

/// it is expected that each element x is (0 <= x <= 1)
pub type BitString = Vec<u8>;


/// Represents a slice, which is a 5x5 matrix.
pub type StateSlice = [[u8;5];5];

/// Represents the 3-dimentional state, which is of size 5 x 5 x w, each value is a bit.
/// 
/// The notion "A\[x,y,z\]" should be accessed via A\[z\]\[x\]\[y\] in code.
pub type State = Vec<StateSlice>;


/// represents "C\[x,z\]" and "D\[x,z\]", which should be accessed via CD\[z\]\[x\];
pub type StatePlane = Vec<[u8; 5]>;


pub fn new_slice() -> StateSlice {
    [[0u8;5]; 5]
}

pub fn new_state(w: usize) -> State {
    let mut A = State::with_capacity(w);
    for _z in 0..w {
        A.push(new_slice());
    }
    A
}

pub fn new_plane(w: usize) -> StatePlane {
    let mut plane = StatePlane::with_capacity(w);
    for _z in 0..w {
        plane.push([0u8; 5]);
    }
    plane
}
