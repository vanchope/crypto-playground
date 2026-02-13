
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

// State conversion functions
pub fn bitstring_to_state(bits: &BitString) -> State {
    let b = bits.len();
    assert!(b==1600); // this is hardcoded for SHA3 functions
    let w = 64;
    //let el = 6;

    let mut a = State::with_capacity(w);
    for _k in 0..w {
        let state_slice: StateSlice = [[0; 5]; 5];
        a.push(state_slice);
    }

    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                a[z][x][y] = bits[w*(5*y+x)+z];
            }
        }
    }    
    a
}

pub fn state_to_bitstring(a: &State) -> BitString {
    let w = a.len();
    
    // w and b are hardcoded for now as per SHA3 definitions
    assert!(w==64); 
    let b = 1600;

    let mut s = BitString::with_capacity(b);
    for _i in 0..b {
        s.push(0);
    }
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                // here, we just duplicate the inverse code of the opposite conversion function
                s[w*(5*y+x)+z] = a[z][x][y];
            }
        }
    }
    s
}

pub fn get_state_value(state_flat:&[u8], z:usize, x:usize, y:usize) -> u8 {
    let w = state_flat.len() / 25;
    state_flat[w*(5*y+x)+z]
}

pub fn set_state_value(state_flat:&mut [u8], z:usize, x:usize, y:usize, val: u8){
    let w = state_flat.len() / 25;
    state_flat[w*(5*y+x)+z] = val;
}



/// Returns a new truncated BitString by copying the first "s" bits.
pub fn trunc(s: usize, x: &BitString) -> BitString {
    let mut x1 = BitString::with_capacity(s);
    for i in 0..s {
        x1.push(x[i]);
    }
    x1
}


/// Returns a new BitString by prepending 0 to the beginning of the old BitString.
pub fn prepend_zero(x: &BitString) -> BitString {
    let len = x.len();
    let mut x1 = BitString::with_capacity(len+1);
    x1.push(0);
    for i in 0..len {
        x1.push(x[i]);
    }
    x1
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


pub fn debug_state_as_bytes(title: &str, a: &State) {
    let w = a.len();
    let len_bytes = w * 5 * 5 / 8;
    let bit_str = state_to_bitstring(a);
    let byte_str = bitstring_to_bytestr(&bit_str);
    let hex =  hex::encode(&byte_str.as_slice());
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

pub fn debug_state_as_lanes_of_integers(title: &str, a: &State) {
    let w = a.len();
    assert!(w==64);
    println!("{title} (as lanes):");
    for x in  0..5 {
        for y in 0..5 {
            let mut lane_bits = BitString::new();
            for z in 0..w {
                lane_bits.push(a[z][x][y]);
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

    fn debug_state(title: &str, a: &State) {
        let w = a.len();
        println!("{title} of w={w} :");
        println!("debug -- begin of state");
        for z in 0..w {
            for x in 0..5 {
                for y in 0..5 {
                    let el = a[z][x][y];
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
    fn test_state_conversion(){
        let mut s = BitString::new();
        let w = 64; // hardcoded for SHA3
        let bit_len = w * 5 * 5;
        
        for i in 0..bit_len {
            s.push((i % 7 % 2) as u8); 
        }
        debug_vec("S", s.as_slice());

        let a = bitstring_to_state(&s);
        //debug_state("A", &A);
        debug_state_as_bytes("A", &a);

        let s1 = state_to_bitstring(&a);
        assert_eq!(s1.as_slice(), s.as_slice());
    }

    #[test]
    fn test_truncate(){
        let x = BitString::from(vec![1, 0, 1, 0, 0]);
        let x1 = trunc(2, &x);
        let expected: [u8; 2] = [1, 0];
        assert_eq!(expected, x1.as_slice());
    }

    #[test]
    fn test_prepend_zero(){
        let x = BitString::from(vec![1, 1]);
        let x1 = prepend_zero(&x);
        let expected: [u8; 3] = [0, 1, 1];
        assert_eq!(expected, x1.as_slice());
    }

    #[test]
    fn test_xor_bitstrings(){
        let x0 = BitString::from(vec![0, 0, 1, 1]);
        let x1 = BitString::from(vec![0, 1, 0, 1]);
        let expected = BitString::from(vec![0, 1, 1, 0]);

        let x2 = xor_bitstrings(&x0, &x1);
        assert_eq!(expected.as_slice(), x2.as_slice());
    }

    #[test]
    fn test_concat_bitstrings(){
        let x0 = BitString::from(vec![0, 0, 1, 1]);
        let x1 = BitString::from(vec![0, 1, 0, 1]);
        let expected = BitString::from(vec![0, 0, 1, 1, 0, 1, 0, 1]);

        let x2 = concat_bitstrings(&x0, &x1);
        assert_eq!(expected.as_slice(), x2.as_slice());
    }
}
