
use crate::sha3::constants::KECCAK_B;
use crate::sha3::constants::KECCAK_NR;
use crate::sha3::constants::RHO_OFFSETS;
use crate::sha3::constants::get_el_from_b;
use crate::sha3::constants::get_w_from_b;
use crate::sha3::types::State;
use crate::sha3::types::BitString;
use crate::sha3::types::new_plane;
use crate::sha3::types::new_state;
use crate::sha3::utils::bitstring_to_bytestr;
use crate::sha3::utils::bitstring_to_state;
use crate::sha3::utils::bytestr_to_bitstring;
use crate::sha3::utils::concat_bitstrings;
use crate::sha3::utils::debug_state_as_bytes;
use crate::sha3::utils::debug_state_as_lanes_of_integers;
use crate::sha3::utils::encode_hex;
use crate::sha3::utils::new_bitstring;
use crate::sha3::utils::prepend_zero;
use crate::sha3::utils::state_to_bitstring;
use crate::sha3::utils::trunc;
use crate::sha3::utils::xor_bitstrings;

/// 1st transformation function (Alg 1., p.11)
fn theta(A: &State) -> State {
    let w = A.len();

    //Step 1.
    let mut C = new_plane(w);
    for x in 0..5 {
        for z in 0..w {
            C[z][x] = A[z][x][0] ^ A[z][x][1] ^ A[z][x][2] ^ A[z][x][3] ^ A[z][x][4];
        }
    }

    // Step 2.
    let mut D = new_plane(w);
    for x in 0..5 {
        for z in 0..w {
            let xi = x as i32;
            let wi = w as i32;
            let zi = z as i32;
            D[z][x] = C[z][((xi-1+5) % 5) as usize] ^ C[((zi-1+wi) % wi)as usize][(x+1) % 5];
        }
    }

    // Step 3.
    let mut A1 = new_state(w);
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                A1[z][x][y] = A[z][x][y] ^ D[z][x];
            }
        }
    }        
    A1
}


/// 2nd transformation function (Alg 2., p.12)
fn rho(A: &State) -> State {
    let w = A.len();
    let mut A1 = new_state(w);
    
    //Step 1.
    for z in 0..w {
        A1[z][0][0] = A[z][0][0];
    }

    //Step 2.
    let (mut x, mut y) = (1, 0);
    
    //Step 3.  For t from 0 to 23:
    for t in 0..24 {
        for z in 0..w {
            let zi = z as i32;
            let wi = w as i32;
            let mut z1 = (zi - (t+1)*(t+2)/2) % wi;
            if z1 < 0 {
                z1 += wi;
            }
            assert!(z1>=0);
            assert_eq!(z1, (zi - RHO_OFFSETS[x][y] + 5*wi) % wi);
            A1[z][x][y] = A[z1 as usize][x][y];
        }
        (x, y) = (y, (2*x + 3*y) % 5);
    }

    // Step 3. Return A1
    A1
}


/// 3rd transformation (Alg 3.)
fn pi(A: &State) -> State {
    let w = A.len();
    let mut A1 = new_state(w);
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                A1[z][x][y] = A[z][(x + 3*y) % 5][x];
            }
        }
    }
    A1
}

/// 4th transformation function (Alg 4.)
fn chi(A: &State) -> State {
    let w = A.len();
    let mut A1 = new_state(w);
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                let tmp1 = A[z][(x+1) % 5][y] ^ 1;
                let tmp2 = A[z][(x+2) % 5][y];
                let tmp = tmp1 * tmp2;
                A1[z][x][y] = A[z][x][y] ^ tmp;
            }
        }
    }
    A1
}


/// RC function (Alg.5), which returns a bit.
/// 
/// input t: integer.
/// 
///    This function is used in Alg. 6 with non-negative values of t.
fn rc(t: usize) -> u8 {
    
    // Step 1.
    if t % 255 == 0 {
        return 1
    }
    
    // Step 2.   R = 1 0 0 0 0 0 0 0   (8 bits with R[0]=1, rest are 0s).
    let mut R = BitString::with_capacity(8);
    R.push(1);
    for _i in 1..8 {
        R.push(0);
    }

    // Step 3.  For i from 1 to t mod 255, let: <...>
    for _ in 1..(t % 255)+1 {
        R = prepend_zero(&R);
        R[0] = R[0] ^ R[8];
        R[4] = R[4] ^ R[8];
        R[5] = R[5] ^ R[8];
        R[6] = R[6] ^ R[8];
        R = trunc(8, &R);
    }

    // Step 4. Return R[0]
    R[0]
}


/// 5th transformation (Alg 6.)
fn iota(A: &State, ir: usize, el: usize) -> State {
    let w = A.len();
    
    // Hardcoded for SHA-3
    //assert!(w==64);
    //let el = 6;

    let mut A1 = new_state(w);

    //Step 1.
    for x in 0..5 {
        for y in 0..5 {
            for z in 0..w {
                A1[z][x][y] = A[z][x][y];
            }
        }
    }

    //Step 2.
    let mut RC = new_bitstring(w);

    // Step 3. For j from 0 to l, let RC[2**j – 1] = rc(j + 7ir)
    for j in 0..(el+1) { // FIXME clarify boundary conditions
        RC[(1<<j)-1] = rc(j + 7 * ir);
    }

    // Step 4.
    for z in 0..w {
        A1[z][0][0] = A1[z][0][0] ^ RC[z];
    }

    // Step 5. Return A'
    A1
}

/// Rnd function (see page 16, Sec. 3.3, of the specs).
///    we explicitly specify "el" as input here
fn rnd(A: &State, ir: usize, el: usize) -> State {
    // println!("\nRound {ir}\n");
    let A1 = theta(A);
    // debug_state_as_bytes("After Theta", &A1);
    let A2 = rho(&A1);
    // debug_state_as_bytes("After Rho", &A2);
    let A3 = pi(&A2);
    // debug_state_as_bytes("After Pi", &A3);
    let A4 = chi(&A3);
    // debug_state_as_bytes("After Chi", &A4);
    let A5 = iota(&A4, ir, el);
    // debug_state_as_bytes("After Iota", &A5);
    A5
}

// Alg 7.
//
// b : width, the fixed length of the permuted strings
// it can be one of {25, 50, 100, 200, 400, 800, 1600}
// it maps to a 5 x 5 x w state.
//
// nr : number of rounds
//
// s : an input string of length b; represented as an array of bytes
fn keccak_p(b: usize, nr: usize, S: &BitString) -> BitString {    
    //let w = get_w_from_b(b);
    let el = get_el_from_b(b);
    assert_eq!(b, S.len());

    // Step 1. Convert S to A
    let mut A = bitstring_to_state(S);

    // debug_state_as_bytes("keccak_p / Step 1 / A", &A);
    // debug_state_as_lanes_of_integers("keccak_p / Step 1 / A", &A);

    // Step 2.   ir  from (12 + 2 el – nr) to  (12 + 2 el – 1)
    for ir in (12 + 2 * el - nr)..(12 + 2 * el) {
        A = rnd(&A, ir, el);
    }    
    // Step 3. Convert A to S' of length b
    let s1 = state_to_bitstring(&A);
    assert_eq!(s1.len(), b as usize);
    s1
}

// we hardcode Sponge function here, as their paramters are mostly fixed (except "c") as per Sec.5.2
//     KECCAK[c] = SPONGE[KECCAK-p[1600, 24], pad10*1, 1600 – c].
//
//   where SPONGE is defined in Alg. 8 as   
//            SPONGE[f, pad, r](N, d)
//
// c : 
fn keccak(keccak_c: usize, N: &BitString, d: usize) -> BitString {
    // hardcoded for SHA3
    let b = KECCAK_B;
    let nr = KECCAK_NR;

    assert!(b > keccak_c);
    let r: usize = b - keccak_c;

    //Step 1 of SPONGE
    let pad = pad101(r as i32, N.len() as i32);
    let mut P = BitString::from(N.as_slice());
    pad.iter().for_each(|el| P.push(*el)); // P = N || pad
    
    //Steps 2-3
    let n = P.len() / r;
    let c = b - r; // === keccak_c

    //Step 4. Split P to n substrings of len r
    //let mut Ps: Vec<BitString> = Vec::new();
    let mut Ps: Vec<&[u8]> = Vec::new();
    for i in 0..n {
        let slice = &P[r*i..r*(i+1)];
        //let mut Pi = BitString::with_capacity(r);
        //slice.iter().for_each(|el| Pi.push(*el));
        //Ps.push(Pi);
        Ps.push(slice);
    }   

    //Step 5.
    let mut S = new_bitstring(b);

    //Step 6.  For i from 0 to n-1, let <..>
    for i in 0..n {
        let zero = new_bitstring(c);
        let Pi_zero = concat_bitstrings(&Ps[i], &zero);
        let f_input = xor_bitstrings(&S, &Pi_zero);
        S = keccak_p(b, nr, &f_input);
    }
    
    //Step 7.
    let mut Z = BitString::new(); // can we estimate the max capacity?
    
    loop {
        //Step 8.
        Z = concat_bitstrings(&Z, &trunc(r, &S));

        //Step 9.
        if d <= Z.len() {
            return trunc(d, &Z)
        }

        //Step 10. update S and go to Step 8
        S = keccak_p(b, nr, &S);
    }

}

/// Alg. 9
/// output a string of the form 10*1
///   x: positive
///   m: non-negative 
fn pad101(x: i32,  m: i32) -> BitString {
    assert!(x>0);
    assert!(m>=0);
    let mut j = (-m -2) % x; 
    if j<0 {
        j += x;
    }
    assert!(j>=0);
    let mut res = BitString::new();
    res.push(1);
    for _ in 0..j {
        res.push(0);
    }
    res.push(1);
    res
}

// two-bit suffixes are applied to M in the sha3 family of functions
pub fn sha3_family(m: &[u8], keccak_c: usize, keccak_d: usize) -> String {
    let mut n = bytestr_to_bitstring(m);
    n.push(0);
    n.push(1);
    let digest_bits = keccak(keccak_c, &n, keccak_d);
    let digest_bytes = bitstring_to_bytestr(&digest_bits);
    let digest_hex = encode_hex(&digest_bytes);
    digest_hex
}

pub fn sha3_224(m:  &[u8]) -> String {
    sha3_family(m, 448, 224)
}

/// The function is defined as follows: SHA3-256(M) = KECCAK [512] (M || 01, 256)
pub fn sha3_256(m: &[u8]) -> String {
    sha3_family(m, 512, 256)
}

pub fn sha3_384(m: &[u8]) -> String {
    sha3_family(m,  768, 384)
}

pub fn sha3_512(m: &[u8]) -> String {
    sha3_family(m,  1024, 512)
}


#[cfg(test)]
mod tests {
    use crate::sha3::utils::decode_hex;

    use super::*;

    fn test_sha3_on_input(bytes: &[u8], expected_digest: &str, sha3_variant: &str){
        let computed_digest = match sha3_variant {
            "sha3-224" => sha3_224(bytes),
            "sha3-256" => sha3_256(bytes),
            "sha3-384" => sha3_384(bytes),
            "sha3-512" => sha3_512(bytes),
            _ => panic!()
        };        
        //println!("Digest for bytes {bytes:?} : {computed_digest}");
        assert_eq!(&expected_digest.to_lowercase(), &computed_digest.to_lowercase());
    }    

    #[test]
    fn test_empty_string(){
        test_sha3_on_input(&[], "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "sha3-256");
    }

    
    // #[test]
    // fn test_5_bits(){ 
    //     test_on_input(&[1, 1, 0, 0, 1], "7B0047CF5A456882363CBF0FB05322CF65F4B7059A46365E830132E3B5D957AF");
    // }

    #[test]
    fn test_2_bytes(){
        test_sha3_on_input(&decode_hex("e9").unwrap(), "f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6", "sha3-256");
    }


    use std::fs::read_to_string;
    fn read_lines(filename: &str) -> Vec<String> {
        read_to_string(filename)
            .unwrap()  // panic on possible file-reading errors
            .lines()  // split the string into an iterator of string slices
            .map(String::from)  // make each slice into a string
            .collect()  // gather them together into a vector
    }
    
    fn test_rsp_file(filename: &str, sha3_variant: &str){
        let lines = read_lines(filename);
        let n = lines.len();                
        println!("file read {filename} -> {n} lines");

        let mut number_of_tests = 0;
        for i in 0..n-2 {
            let line = &lines[i];
            if line.starts_with("Len") {
                number_of_tests += 1;
                let len_bytes: i32 = line.split("=").skip(1).next().unwrap().trim().parse().unwrap();
                
                let line_msg = &lines[i+1];
                let msg_hex = line_msg.split("=").skip(1).next().unwrap().trim();
                let msg_len = msg_hex.len();
                if len_bytes > 0 {  // len 0 test has input msg as 00.
                    assert_eq!(msg_len * 4, len_bytes as usize);
                }
                
                let line_md = &lines[i+2];
                let md = line_md.split("=").skip(1).next().unwrap().trim();

                let msg_hex_to_show = match msg_hex.len() {
                    ..17 => msg_hex.to_string(),
                    17.. => msg_hex[..4].to_string() + "..." + &msg_hex[msg_hex.len()-4..]
                };
                println!("Found test #{number_of_tests}: Len = {len_bytes}, Msg [of len {msg_len}] = {msg_hex_to_show}");
                println!("expected MD = '{md}'");

                let decoded_input = decode_hex(msg_hex).unwrap();
                // this takes care of len 0 test case that has input msg as 00 (msg len and Len mismatch).
                let decoded_input_corrected = &decoded_input[0..(len_bytes/8) as usize];
                test_sha3_on_input(&decoded_input_corrected, md, sha3_variant);
            }
        }
    }


    #[test]
    fn test_rsp_224_file(){
        test_rsp_file("test_vectors/SHA3/SHA3_224ShortMsg.rsp", "sha3-224");
    }

    #[test]
    fn test_rsp_256_file(){
        test_rsp_file("test_vectors/SHA3/SHA3_256ShortMsg.rsp", "sha3-256");
    }

    #[test]
    fn test_rsp_256_long_file(){
        test_rsp_file("test_vectors/SHA3/SHA3_256LongMsg.rsp", "sha3-256");
    }

    #[test]
    fn test_rsp_384_file(){
        test_rsp_file("test_vectors/SHA3/SHA3_384ShortMsg.rsp", "sha3-384");
    }

    #[test]
    fn test_rsp_512_file(){
        test_rsp_file("test_vectors/SHA3/SHA3_512ShortMsg.rsp", "sha3-512");
    }

    #[test]
    fn test_read_file(){
        use std::fs;
        let filename = "test/test_file.txt";
        let data = fs::read(filename).unwrap();
        let data_bytes = data.len();
        let computed_digest = sha3_256(&data).to_lowercase();
        println!("reading file '{filename}' => len {data_bytes} bytes; bytes => {data:?} \n: digest = {computed_digest}");
    }
 
}
