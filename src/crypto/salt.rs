use crate::enums::HashAlgorithm;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;

/// The `MAX_SALT_SIZE` constant represents the maximum size, in bytes, 
/// allowed for a salt value in certain cryptographic operations.
///
/// # Value
/// - The value of `MAX_SALT_SIZE` is set to `256`.
///
/// # Usage
/// This constant can be used to enforce constraints on the size of 
/// salt values when generating or validating them, ensuring consistency 
/// and security in cryptographic implementations.
///
/// # Type
/// - `u16`: The constant is of type `u16` (16-bit unsigned integer), 
///   which means the value range is between `0` and `65535`.
///
/// # Example
/// ```rust
/// const MAX_SALT_SIZE: u16 = 256;
/// let salt = vec![0u8; MAX_SALT_SIZE as usize];
/// assert_eq!(salt.len(), 256); // Confirms the salt length matches `MAX_SALT_SIZE`
/// ```
const MAX_SALT_SIZE: u16 = 256;

/// Generates a cryptographically secure random salt of the specified size.
///
/// # Parameters
/// - `desired_size`: A `u16` value representing the desired size of the salt to generate.
///   - This value must not exceed the maximum salt size defined by `MAX_SALT_SIZE`.
///
/// # Returns
/// A 256-byte array (`[u8; 256]`) containing the randomly generated salt.
///
/// # Panics
/// This function will panic if the `desired_size` parameter exceeds the maximum allowed size,
/// which is defined by the constant `MAX_SALT_SIZE`.
///
/// # Behavior
/// - The function uses the `OsRng` cryptographic random number generator to fill a buffer
///   with high-entropy random bytes.
/// - The output buffer is always fixed at 256 bytes, but actual usage may involve slicing it to
///   the desired size depending on the passed `desired_size`.
///
/// # Example
/// ```
/// const MAX_SALT_SIZE: u16 = 256;
///
/// let salt = generate_salt(16);
/// assert_eq!(salt.len(), 256); // Buffer is fixed at 256 bytes
/// // Slice as necessary for the desired size
/// let sliced_salt = &salt[..16];
/// assert_eq!(sliced_salt.len(), 16);
/// ```
///
/// # Security
/// This function is designed to generate cryptographically secure random values, suitable
/// for use in password hashing, cryptographic key generation, and other security-critical applications.
///
/// # Notes
/// - Ensure that `MAX_SALT_SIZE` is appropriately defined before using this function.
/// - This implementation currently disregards the `desired_size` and returns a complete 256-byte buffer.
///   It is the caller's responsibility to slice the buffer if necessary.
///
/// # Dependencies
/// - The `rand` crate for access to `OsRng`.
///
pub fn generate_salt(desired_size: u16) -> [u8; 256] {
    // Ensure the desired size does not exceed the maximum salt size.
    if desired_size > MAX_SALT_SIZE {
        panic!(
            "Desired salt size exceeds the maximum buffer size of {}",
            MAX_SALT_SIZE
        );
    }

    // Initialize a 256-byte buffer with random data
    let mut salt_buffer = [0u8; MAX_SALT_SIZE as usize];
    OsRng::fill_bytes(&mut OsRng, &mut salt_buffer);
    salt_buffer
}

/// Returns the recommended salt size in bytes for the specified hash algorithm.
///
/// The salt size is determined based on the cryptographic hash algorithm provided
/// and aligns with commonly accepted standards for ensuring security. Using
/// the recommended salt size helps in mitigating risks such as rainbow table attacks.
///
/// # Arguments
///
/// * `hash_algorithm` - A hash algorithm from the `HashAlgorithm` enum for which
///                       the recommended salt size is to be determined.
///
/// # Returns
///
/// A `u16` value representing the recommended salt size in bytes.
///
/// # Supported Hash Algorithms and Recommendations
///
/// * `HashAlgorithm::Sha224` -> 16 bytes
/// * `HashAlgorithm::Sha512_224` -> 16 bytes
/// * `HashAlgorithm::Sha256` -> 32 bytes
/// * `HashAlgorithm::Sha512_256` -> 32 bytes
/// * `HashAlgorithm::Sha384` -> 48 bytes
/// * `HashAlgorithm::Sha512` -> 64 bytes
///
/// # Example
///
/// ```
/// use your_crate_name::HashAlgorithm;
/// use your_crate_name::recommend_salt_size;
///
/// let salt_size = recommend_salt_size(HashAlgorithm::Sha256);
/// assert_eq!(salt_size, 32);
/// ```
///
/// This function ensures that the salt size aligns with the best practices for the
/// provided hash algorithm.
pub fn recommend_salt_size(hash_algorithm: HashAlgorithm) -> u16 {
    match hash_algorithm {
        HashAlgorithm::Sha224 => 16,
        HashAlgorithm::Sha512_224 => 16,
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha512_256 => 32,
        HashAlgorithm::Sha384 => 48,
        HashAlgorithm::Sha512 => 64,
    }
}
