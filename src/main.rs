use crypto_playground::sha3::{sha3, types::{BitString, ByteString}};

fn main() {
    let m = "Test";
    let bytes = m.as_bytes();
    let digest = hex::encode(sha3::sha3_256(bytes).as_slice());
    println!("Digest for '{m}' : {digest}");

    //let bytes = ByteString::from(vec![1, 1, 0, 0, 1]);
}
