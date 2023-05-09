// Copyright 2023 Web3 Developer @ Web3Developer.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A lightweight library which provides a fluent interface for generating SHA-1 and SHA-2 digests.

use std::fs::File;
use std::io::{BufRead, BufReader};
use ring::digest as r_digest;


/// The hashing algorithm. SHA-1 and SHA2 algorithms are supported.
#[derive(Debug, Eq, PartialEq)]
pub enum Hashing {
    /// The SHA1 hash algorithm. Should generally be avoided unless working with legacy software.
    Sha1,
    /// The SHA2 256 bit hash algorithm.
    Sha256,
    /// The SHA2 384 bit hash algorithm.
    Sha384,
    /// The SHA2 512 bit hash algorithm.
    Sha512,
    /// The SHA2 512-256 bit hash algorithm. Uses SHA-512 but returns only 256 bits.
    Sha512_256,
}

impl Hashing {

    /// Creates a new instance of a `HashContext` to be used with the selected `Hashing` algorithm.
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

    /// Returns a `Hash` of the given byte array `data`.
    pub fn hash(&self, data: &[u8]) -> Hash {
        let mut ctx = self.new_context();
        ctx.update(data);
        ctx.finish()
    }

    /// Returns a `Hash` of the given byte vector `data`.
    #[inline]
    pub fn hash_vec(&self, data: Vec<u8>) -> Hash {
        self.hash(data.as_ref())
    }

    /// Returns a `Hash` of the given string `data`.
    #[inline]
    pub fn hash_str(&self, data: &str) -> Hash {
        self.hash(data.as_ref())
    }

    /// Returns a `Hash` of the file located at the given path.
    /// Fails if the file doesn't exist or can't be opened.
    pub fn hash_file(&self, path: &str) -> Hash {
        // TODO: improve the error handling here to allow catching errors without panic
        let file = File::open(path).expect(&format!("Failed to open file with path: {}", path));
        let reader = BufReader::new(file);

        let mut ctx = self.new_context();
        for line in reader.lines() {
            ctx.update(line.unwrap().as_bytes());
        }

        ctx.finish()
    }

}



/// A context to be used for multi-step hash calculations.
/// Useful when hashing a data structure with multiple fields or when hashing larger inputs.
#[derive(Clone)]
pub struct HashContext(r_digest::Context);

impl HashContext {

    /// Updates the `HashContext` with the given byte array `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the `Hash` from the data in the `HashContext`.
    /// Consumes the `HashContext` so it cannot reused after calling finish.
    #[inline]
    pub fn finish(self) -> Hash {
        Hash(self.0.finish())
    }

}


/// A hash value which holds the message digest produced by one of the `Hashing` algorithms.
/// Supports formatting as a byte array, byte vector or a hexadecimal string.
#[derive(Clone, Copy)]
pub struct Hash(r_digest::Digest);

impl Hash {

    /// Returns a reference to the hash value bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns the hash value as a vector of bytes.
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Returns the hash value as a hexadecimal string.
    #[inline]
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