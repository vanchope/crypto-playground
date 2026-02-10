use crypto_playground::sha3::sha3;

fn main() {
    let m = "Test";
    let bytes = m.as_bytes();
    let digest = sha3::sha3_256(bytes);
    println!("Digest for '{m}' : {digest}");
}
