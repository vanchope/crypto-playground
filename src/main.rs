use crypto_playground::sha3::{sha3::{Sha3}, types::{Sha3Variant}};

fn main() {
    let m = "Test";
    let bytes = m.as_bytes();
    let sha3_256 = Sha3::new(Sha3Variant::SHA3_256);
    let digest = hex::encode(sha3_256.compute_digest(bytes).as_slice());
    println!("Digest for '{m}' : {digest}");

    //let bytes = ByteString::from(vec![1, 1, 0, 0, 1]);
}
