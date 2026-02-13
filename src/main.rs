use crypto_playground::sha3::{sha3, types::{BitString, ByteString}};

fn main() {
    // let m = "Test";
    // let bytes = m.as_bytes();
    // let digest = sha3::sha3_256(bytes);
    // println!("Digest for '{m}' : {digest}");

    let bytes = ByteString::from(vec![1, 1, 0, 0, 1]);
    let digest = sha3::sha3_256(&bytes);
    println!("Digest : {digest}");
}
