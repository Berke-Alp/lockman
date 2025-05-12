use bincode::{Decode, Encode};

// TODO: Only Aes256Gcm supported for initial commit, further implementations are WIP
#[derive(Encode, Decode, Debug)]
pub enum LockMode {
    Aes128Gcm = 1,
    Aes256Gcm = 2,
}

/// An enumeration representing various hash algorithms supported in this application.
///
/// This enum provides a set of predefined constants that correspond to specific cryptographic hash algorithms.
/// Each variant is assigned a unique discriminant value which can be used in mapping or serialization tasks.
///
/// # Variants
///
/// * `Sha224` - Represents the SHA-224 hash algorithm.
/// * `Sha512_224` - Represents the SHA-512/224 hash algorithm.
/// * `Sha256` - Represents the SHA-256 hash algorithm.
/// * `Sha512_256` - Represents the SHA-512/256 hash algorithm.
/// * `Sha384` - Represents the SHA-384 hash algorithm.
/// * `Sha512` - Represents the SHA-512 hash algorithm.
///
/// # Example
///
/// ```rust
/// use my_crate::HashAlgorithm;
///
/// let algorithm = HashAlgorithm::Sha256;
///
/// match algorithm {
///     HashAlgorithm::Sha256 => println!("SHA-256 selected."),
///     _ => println!("Another hash algorithm selected."),
/// }
/// ```
pub enum HashAlgorithm {
    Sha224 = 0,
    Sha512_224 = 1,
    Sha256 = 2,
    Sha512_256 = 3,
    Sha384 = 4,
    Sha512 = 5,
}