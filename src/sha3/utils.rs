use crate::sha3::types::State;
use crate::sha3::types::StateSlice;
use crate::sha3::types::BitString;
use crate::sha3::types::ByteString;


/// Converts an array of bytes to an array of bits, where each bit is of type u8.
/// 
/// [4] ==> \[00000100\] => \[0, 0, 1, 0, 0, 0, 0, 0\]
pub fn bytestr_to_bitstring(bytes: &[u8]) -> BitString {
    let bytes_len = bytes.len();
    let mut bits = BitString::new();
    for i in 0..bytes_len {
        for offset in 0..8 {
            let bit =  (bytes[i] >> offset) & 1;
            bits.push(bit);
        }
    }
    bits
}

/// Converts an array of bits (of u8 type) to an array of bytes.
/// 
/// \[0, 0, 1, 0, 0, 0, 0, 0\] => \[00000100\] => \[4\]
pub fn bitstring_to_bytestr(bits: &[u8]) -> ByteString {
    assert!(bits.len() % 8 == 0);
    let bytes_len = bits.len() / 8;
    let mut res = ByteString::with_capacity(bytes_len);
    for i in 0..bytes_len {
        let mut byte: u8 = 0;
        for offset in 0..8 {
            let bit = bits[8*i + offset];
            byte |= bit << offset;
        }
        res.push(byte);
    }
    res
}

/// Encodes bytes into 2 characters 0-9A-F.
pub fn encode_hex(bytes: &ByteString) -> String {
    bytes.iter().map(|c| format!("{:02X}", c)).collect()
}


// source: https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
use std::num::ParseIntError;
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}


// State conversion functions
pub fn bitstring_to_state(bits: &BitString) -> State {
    let b = bits.len();
    assert!(b==1600); // this is hardcoded for SHA3 functions
    let w = 64;
    //let el = 6;

    let mut A = State::with_capacity(w);
    for _k in 0..w {
        let state_slice: StateSlice = [[0; 5]; 5];
        A.push(state_slice);
    }

    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                A[z][x][y] = bits[w*(5*y+x)+z];
            }
        }
    }    
    A
}

pub fn state_to_bitstring(A: &State) -> BitString {
    let w = A.len();    
    
    // w and b are hardcoded for now as per SHA3 definitions
    assert!(w==64); 
    let b = 1600;

    let mut S = BitString::with_capacity(b);
    for _i in 0..b {
        S.push(0);
    }
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                // here, we just duplicate the inverse code of the opposite conversion function
                S[w*(5*y+x)+z] = A[z][x][y];
            }
        }
    }
    S
}


/// Returns a new truncated BitString by copying the first "s" bits.
pub fn trunc(s: usize, X: &BitString) -> BitString {
    let mut X1 = BitString::with_capacity(s);
    for i in 0..s {
        X1.push(X[i]);
    }
    X1
}


/// Returns a new BitString by prepending 0 to the beginning of the old BitString.
pub fn prepend_zero(X: &BitString) -> BitString {
    let len = X.len();
    let mut X1 = BitString::with_capacity(len+1);
    X1.push(0);
    for i in 0..len {
        X1.push(X[i]);
    }
    X1
}

/// Returns a new BitString of size w initialized to 0s.
pub fn new_bitstring(w: usize) -> BitString {
    let mut bs = BitString::with_capacity(w);
    for _ in 0..w {
        bs.push(0);
    }
    bs
}

/// Performs a xor operation on two BitStrings of equal length.
pub fn xor_bitstrings(bs0: &BitString, bs1: &BitString) -> BitString {
    assert_eq!(bs0.len(), bs1.len());
    let len = bs0.len();
    let mut bs2 = BitString::with_capacity(len);
    for i in 0..len {
        let bit = bs0[i] ^ bs1[i];
        bs2.push(bit);
    }
    bs2
}

// Concats Bitstings bs1 and bs2 to bs1 || bs2.
//pub fn concat_bitstrings(bs0: &BitString, bs1: &BitString) -> BitString {
pub fn concat_bitstrings(bs0: &[u8], bs1: &[u8]) -> BitString {
    let len0 = bs0.len();
    let len1 = bs1.len();
    let mut bs2 = BitString::with_capacity(len0 + len1);
    for i in 0..len0 {
        bs2.push(bs0[i]);
    }
    for i in 0..len1 {
        bs2.push(bs1[i]);
    }
    bs2
}


pub fn debug_state_as_bytes(title: &str, A: &State) {
    let w = A.len();
    let len_bytes = w * 5 * 5 / 8;
    let bit_str = state_to_bitstring(A);
    let byte_str = bitstring_to_bytestr(&bit_str);
    let hex = encode_hex(&byte_str);
    //println!("{title} : \n{hex}");
    println!("{title} :");

    for i in 0..len_bytes {
        let substr = &hex[2*i..2*i+2];
        print!("{substr} ");
        if i>0 && i%16==15 {
            println!();
        }
    }
    println!();
}

pub fn debug_state_as_lanes_of_integers(title: &str, A: &State) {
    let w = A.len();
    assert!(w==64);
    println!("{title} (as lanes):");
    for x in  0..5 {
        for y in 0..5 {
            let mut lane_bits = BitString::new();
            for z in 0..w {
                lane_bits.push(A[z][x][y]);
            }
            // We display bits (a0 a1 a2 ...) as integer  ...a2a1a0.
            let mut lane_u64: u64 = 0;
            for z in 0..w {
                lane_u64 |= (lane_bits[z] as u64 & 1) << z;
            }
            println!("  [{x}][{y}] = {lane_u64:016X}");
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn debug_vec(title: &str, ar: &[u8]) {
        let len = ar.len();
        println!("{title} of len {len} :");
        for i in 0..len {
            let el = ar[i];
            print!("{el} ");
        }
        println!();
    }

    fn debug_state(title: &str, A: &State) {
        let w = A.len();
        println!("{title} of w={w} :");
        println!("debug -- begin of state");
        for z in 0..w {
            for x in 0..5 {
                for y in 0..5 {
                    let el = A[z][x][y];
                    print!("{el} ");
                }
                println!();
            }
            println!();
            println!();
        }
        println!("debug -- end of state");
    }
    

    fn test_with_string(s: &str){
        let bytes = s.as_bytes();
        debug_vec("input string as bytes", bytes);

        let bit_string = bytestr_to_bitstring(bytes);
        debug_vec("bit_string", bit_string.as_slice());

        let byte_string = bitstring_to_bytestr(&bit_string);
        debug_vec("byte_string", byte_string.as_slice());
        let bytes_2 = byte_string.as_slice();
        assert_eq!(bytes, bytes_2);
    }

    #[test]
    fn test_str_to_bitstring() {
        test_with_string("Hello");
        test_with_string("");
    }

    #[test]
    fn test_bytestr_to_hex(){
        let bytes = ByteString::from([0, 10, 32, 255]);
        let hex = encode_hex(&bytes);
        println!("{hex}");
        assert_eq!(&hex.to_lowercase(), "000a20ff");

        let vec_2 = decode_hex(&hex).unwrap();
        let bytes_2 = vec_2.as_slice();
        assert_eq!(bytes_2, bytes);
    }

    #[test]
    fn test_state_conversion(){
        let mut S = BitString::new();
        let w = 64; // hardcoded for SHA3
        let bit_len = w * 5 * 5;
        
        for i in 0..bit_len {
            S.push((i % 7 % 2) as u8); 
        }
        debug_vec("S", S.as_slice());

        let A = bitstring_to_state(&S);
        //debug_state("A", &A);
        debug_state_as_bytes("A", &A);

        let S1 = state_to_bitstring(&A);
        assert_eq!(S1.as_slice(), S.as_slice());
    }

    #[test]
    fn test_truncate(){
        let X = BitString::from([1, 0, 1, 0, 0]);
        let X1 = trunc(2, &X);
        let expected: [u8; 2] = [1, 0];
        assert_eq!(expected, X1.as_slice());
    }

    #[test]
    fn test_prepend_zero(){
        let X = BitString::from([1, 1]);
        let X1 = prepend_zero(&X);
        let expected: [u8; 3] = [0, 1, 1];
        assert_eq!(expected, X1.as_slice());
    }

    #[test]
    fn test_xor_bitstrings(){
        let X0 = BitString::from([0, 0, 1, 1]);
        let X1 = BitString::from([0, 1, 0, 1]);
        let expected = BitString::from([0, 1, 1, 0]);

        let X2 = xor_bitstrings(&X0, &X1);
        assert_eq!(expected.as_slice(), X2.as_slice());
    }

    #[test]
    fn test_concat_bitstrings(){
        let X0 = BitString::from([0, 0, 1, 1]);
        let X1 = BitString::from([0, 1, 0, 1]);
        let expected = BitString::from([0, 0, 1, 1, 0, 1, 0, 1]);

        let X2 = concat_bitstrings(&X0, &X1);
        assert_eq!(expected.as_slice(), X2.as_slice());
    }
}
