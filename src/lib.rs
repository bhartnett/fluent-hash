

use std::fs::File;
use std::io::{BufRead, BufReader};
use ring::digest as r_digest;


// Hashing

pub enum Hashing {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha512_256,
}

impl Hashing {

    pub fn new_context(&self) -> HashContext {
        match self {
            Self::Sha1 => HashContext(r_digest::Context::new(
                &r_digest::SHA1_FOR_LEGACY_USE_ONLY)),
            Self::Sha256 => HashContext(r_digest::Context::new(
                &r_digest::SHA256)),
            Self::Sha384 => HashContext(r_digest::Context::new(
                &r_digest::SHA384)),
            Self::Sha512 => HashContext(r_digest::Context::new(
                &r_digest::SHA512)),
            Self::Sha512_256 => HashContext(r_digest::Context::new(
                &r_digest::SHA512_256)),
        }
    }

    pub  fn hash(&self, data: &[u8]) -> Hash {
        let mut ctx = self.new_context();
        ctx.update(data);
        ctx.finish()
    }

    pub fn hash_vec(&self, data: Vec<u8>) -> Hash {
        self.hash(data.as_ref())
    }

    pub fn hash_str(&self, data: &str) -> Hash {
        self.hash(data.as_ref())
    }

    pub fn hash_file(&self, path: &str) -> Hash {
        let file = File::open(path).expect(&format!("Failed to open file with path: {}", path));
        let reader = BufReader::new(file);

        let mut ctx = self.new_context();
        for line in reader.lines() {
            ctx.update(line.unwrap().as_bytes());
        }

        ctx.finish()
    }

}


// Context

pub struct HashContext(r_digest::Context);

impl HashContext {

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> Hash {
        Hash(self.0.finish())
    }

}


// Digest

pub struct Hash(r_digest::Digest);

impl Hash {

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

}


// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hashing::{Sha1, Sha256, Sha384, Sha512, Sha512_256};
    use std::fs::File;
    use std::io::Write;
    use hex::ToHex;

    const DATA_TO_DIGEST: &[u8] = b"Hello, World!";
    const FILE_NAME: &str = "testfile.txt";

    fn create_test_file() {
        // prepare test file
        let mut file = File::create("testfile.txt").unwrap();
        file.write_all(DATA_TO_DIGEST).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn sha256_context() {
        let mut r_ctx = r_digest::Context::new(&r_digest::SHA256);
        r_ctx.update(DATA_TO_DIGEST);
        let expected = r_ctx.finish();

        let mut ctx = Sha256.new_context();
        ctx.update(DATA_TO_DIGEST);
        let result = ctx.finish();

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha1_digest() {
        let expected = r_digest::digest(&r_digest::SHA1_FOR_LEGACY_USE_ONLY, DATA_TO_DIGEST);
        let result = Sha1.hash(DATA_TO_DIGEST);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha384_digest() {
        let expected = r_digest::digest(&r_digest::SHA384, DATA_TO_DIGEST);
        let result = Sha384.hash(DATA_TO_DIGEST);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha512_digest() {
        let expected = r_digest::digest(&r_digest::SHA512, DATA_TO_DIGEST);
        let result = Sha512.hash(DATA_TO_DIGEST);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha512_256_digest() {
        let expected = r_digest::digest(&r_digest::SHA512_256, DATA_TO_DIGEST);
        let result = Sha512_256.hash(DATA_TO_DIGEST);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha256_digest() {
        let expected = r_digest::digest(&r_digest::SHA256, DATA_TO_DIGEST);
        let result = Sha256.hash(DATA_TO_DIGEST);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha256_digest_vec() {
        let expected = r_digest::digest(&r_digest::SHA256, DATA_TO_DIGEST);
        let result = Sha256.hash_vec(DATA_TO_DIGEST.to_vec());

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha256_digest_str() {
        let expected = r_digest::digest(&r_digest::SHA256, DATA_TO_DIGEST);
        let result = Sha256.hash_str(&String::from_utf8(DATA_TO_DIGEST.to_vec()).unwrap());

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

    #[test]
    fn sha256_digest_file() {
        create_test_file();

        let expected = r_digest::digest(&r_digest::SHA256, DATA_TO_DIGEST);
        let result = Sha256.hash_file(FILE_NAME);

        assert_eq!(result.as_bytes(), expected.as_ref());
        assert_eq!(result.to_vec(), expected.as_ref().to_vec());
        assert_eq!(result.to_hex(), expected.encode_hex::<String>());
    }

}