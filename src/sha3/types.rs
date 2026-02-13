use derive_more::{Deref, DerefMut, From, Index, IndexMut};

pub enum Sha3Variant {
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

/// each element x is (0 <= x <= 255)
#[derive(Deref, DerefMut, From, Clone)]
pub struct ByteString(Vec<u8>);

impl ByteString {
    pub fn new() -> Self {
        ByteString(Vec::new())
    } 

    pub fn with_capacity(capacity: usize) -> Self {
        ByteString(Vec::with_capacity(capacity))
    }
}

/// it is expected that each element x is (0 <= x <= 1)
//pub type BitString = Vec<u8>;
#[derive(Deref, DerefMut, From, Clone)]
pub struct BitString(Vec<u8>);

impl BitString {
    pub fn new() -> BitString {
        BitString(Vec::new())
    } 

    pub fn with_capacity(capacity: usize) -> Self {
        BitString(Vec::with_capacity(capacity))
    }
}


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
    let mut a = State::with_capacity(w);
    for _z in 0..w {
        a.push(new_slice());
    }
    a
}

pub fn new_plane(w: usize) -> StatePlane {
    let mut plane = StatePlane::with_capacity(w);
    for _z in 0..w {
        plane.push([0u8; 5]);
    }
    plane
}
