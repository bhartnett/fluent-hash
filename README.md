# Fluent Hash

fluent-hash is a wrapper on top of the <a href = "https://github.com/briansmith/ring"><em>ring</em></a> cryptography 
library which provides a fluent interface for generating SHA-1 and SHA-2 hashes. 

It provides convenience methods for generating hashes from the following types:
- `&[u8]`
- `Vec<u8>`
- `&str`
- `std::fs::File`

It also supports formatting hashes as bytes or hexadecimal.

## Supported Hash Algorithms
The following SHA-1 and SHA-2 algorithms are supported:
- SHA-1 
- SHA-256 
- SHA-384
- SHA-512
- SHA-512_256

## Documentation
See the documentation at: https://docs.rs/fluent-hash/

## Examples

Import the fluent_hash types.
```rust
use fluent_hash::Hashing::Sha1;
use fluent_hash::Hashing::Sha256;
use fluent_hash::Hashing::Sha384;
use fluent_hash::Hashing::Sha512;
use fluent_hash::Hashing::Sha512_256;
use fluent_hash::Hashing;
use fluent_hash::HashContext;
use fluent_hash::Hash;
```

Hash a byte array.
```rust
let result: Hash = Sha256.hash(b"hello, world");
```

Hash a byte vector.
```rust
let result: Hash = Sha256.hash_vec(b"hello, world".to_vec());
```

Hash a string.
```rust
let result: Hash = Sha256.hash_str("hello, world");
```

Hash a file.
```rust
let result: Hash = Sha256.hash_file("file.txt")?;
```

Format the hash.
```rust
let bytes: &[u8] = result.as_bytes();
let bytes_vec: Vec<u8> = result.to_vec();
let hex: String = result.to_hex();
```

See the Web3 Developer blog post which shows more fluent-hash usage examples here: https://web3developer.io/introducing-fluent-hash/

## License
fluent-hash is distributed under the Apache License version 2.0.

## Disclaimer
THE SOFTWARE IS PROVIDED "AS IS" THE AUTHORS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


