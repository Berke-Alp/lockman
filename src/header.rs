//! Constant definition for the magic number representing the LockMan file format.
//! This is verified against the first 16 bytes of a file to ensure compatibility.
use crate::enums::LockMode;
use bincode::{Decode, Encode};

/// A constant array representing the "magic number" or identifier for a specific file format.
///
/// This array is used to identify and verify the file type by comparing the first 16 bytes of a file
/// against this predefined sequence of bytes. It serves as a signature to ensure that the file being read
/// or processed conforms to the expected format.
///
/// The bytes in the array correspond to the ASCII representation of "LOCKMANNED FILE ".
///
/// # Example Usage
/// ```
/// // Example usage to verify if a file begins with FILE_MAGIC:
/// use std::fs::File;
/// use std::io::{Read, Result};
///
/// fn is_valid_file(file_path: &str) -> Result<bool> {
///     let mut file = File::open(file_path)?;
///     let mut buffer = [0u8; 16];
///     file.read_exact(&mut buffer)?;
///     Ok(buffer == FILE_MAGIC)
/// }
/// ```
///
/// # Byte Representation
/// - Array contents:
///   `[0x4C, 0x4F, 0x43, 0x4B, 0x4D, 0x41, 0x4E, 0x4E, 0x45, 0x44, 0x20, 0x46, 0x49, 0x4C, 0x45, 0x20]`
/// - ASCII equivalent:
///   `"LOCKMANNED FILE "`
pub const FILE_MAGIC: [u8; 16] = [
    0x4C, 0x4F, 0x43, 0x4B, 0x4D, 0x41, 0x4E, 0x4E, 0x45, 0x44, 0x20, 0x46, 0x49, 0x4C, 0x45, 0x20,
];

///
/// A structure representing the pre-header of a LockMan file.
///
/// This structure is used to store metadata required for interpreting the LockMan file.
/// It includes a magic number, version information, and the size of the header.
///
/// # Attributes
/// - `magic`:
///   A 16-byte array that represents the magic number, used to identify the file format.
/// - `version`:
///   A 32-bit unsigned integer specifying the version of the LockMan file format.
/// - `header_size`:
///   A 32-bit unsigned integer indicating the size of the header in bytes.
///
/// # Derives
/// - `Encode`:
///   Allows the structure to be encoded into a binary format (e.g., using SCALE codec).
/// - `Decode`:
///   Allows the structure to be decoded from a binary format.
/// - `Debug`:
///   Enables the structure to be formatted using the `{:?}` formatter, useful for debugging.
///
/// # Representation
/// The structure is represented in memory as a C-compatible layout (`#[repr(C)]`),
/// ensuring compatibility with C-based systems and binary file formats.
///
/// # Example
/// ```
/// use some_crate::LockManFilePreHeader; // Assume `LockManFilePreHeader` is imported from a crate.
///
/// let pre_header = LockManFilePreHeader {
///     magic: *b"LOCKMAN_FORMAT",
///     version: 1,
///     header_size: 64,
/// };
/// println!("{:?}", pre_header);
/// ```
#[derive(Encode, Decode, Debug)]
#[repr(C)]
pub struct LockManFilePreHeader {
    pub magic: [u8; 16],
    pub version: u32,
    pub header_size: u32,
}

impl LockManFilePreHeader {
    pub fn new(version: u32, header_size: u32) -> Self {
        let mut _header_size = if header_size == 0 {
            size_of::<LockManFileHeader>() as u32
        } else {
            header_size
        };
        
        Self {
            magic: FILE_MAGIC,
            version,
            header_size: _header_size,
        }
    }
}

/// Represents the file header structure for LockMan, containing metadata 
/// about the locking mechanism and encryption configuration.
///
/// # Fields
///
/// * `lock_mode` - Defines the mode of the locking mechanism being used. 
///   This is represented by the `LockMode` enum, which should provide 
///   the allowed locking modes.
///
/// * `key_iterations` - The number of iterations used for key derivation. 
///   Higher values increase the security of symmetric key generation by 
///   making brute-force attacks slower, at the cost of computational time.
///
/// * `block_size` - The size of each encrypted block in bytes. This value 
///   typically determines the unit size for encrypting data in the file.
///
/// * `block_count` - The total number of blocks in the encrypted file. 
///   This value indicates the total size of the data divided by the 
///   `block_size`.
///
/// * `used_salt_size` - The size (in bytes) of the salt that is actually 
///   used in the key derivation process. This should ideally not exceed 
///   the length of the `salt` array.
///
/// * `salt` - A fixed-size byte array (256 bytes) containing the salt value
///   used during the key derivation process. Salt adds uniqueness to 
///   cryptographic operations, preventing precomputed attacks such as 
///   rainbow table attacks.
#[derive(Encode, Decode, Debug)]
pub struct LockManFileHeader {
    pub lock_mode: LockMode,
    pub key_iterations: u32,
    pub block_size: u32,
    pub block_count: u64,
    pub used_salt_size: u16,
    pub salt: [u8; 256],
}

/// A trait to provide functionality for converting types into a vector of bytes.
///
/// The `ToBytes` trait is implemented for types that can be serialized into a binary
/// representation using the `bincode` crate. The trait requires the type to implement
/// the `bincode::Encode` trait, enabling serialization into a byte vector.
///
/// # Required Methods
/// The trait provides a default implementation for the `to_bytes` method:
///
/// ## `to_bytes`
/// Converts the type implementing `ToBytes` into a `Vec<u8>` containing its binary representation.
///
/// ### Returns
/// - `Ok(Vec<u8>)`: A vector containing the serialized byte representation of the type
///   if the serialization succeeds.
/// - `Err(bincode::error::EncodeError)`: An error if the serialization fails.
///
/// ### Constraints
/// - The type implementing the `ToBytes` trait must also implement `bincode::Encode`.
/// - The size of the type must be determined using `std::mem::size_of::<Self>()`.
///
/// ### Behavior
/// 1. Allocates a `Vec<u8>` with a predefined size equal to the size of the type.
/// 2. Serializes the type using `bincode::encode_into_slice` with a standard `bincode` configuration.
/// 3. On successful encoding, returns the byte vector. If encoding fails, returns an error.
///
/// # Example
///
/// ```
/// use bincode::Encode;
///
/// #[derive(Encode)]
/// struct MyStruct {
///     id: u32,
///     name: String,
/// }
///
/// impl ToBytes for MyStruct {}
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let my_object = MyStruct { id: 1, name: "Alice".to_string() };
///     let bytes = my_object.to_bytes()?;
///     println!("{:?}", bytes);
///     Ok(())
/// }
/// ```
///
/// In this example, a custom type `MyStruct` implements the `ToBytes` trait, which allows
/// converting an instance of `MyStruct` into a vector of bytes for storage or transfer.
///
/// # Note
/// This implementation assumes that the size of the type can be determined at compile time
/// using `std::mem::size_of`. If this assumption is incorrect for the type, the implementation
/// may not work as expected.
pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>, bincode::error::EncodeError>
    where
        Self: Sized + bincode::Encode,
    {
        let mut bytes = vec![0u8; size_of::<Self>()];
        bincode::encode_into_slice(self, &mut bytes, bincode::config::standard())?;
        Ok(bytes)
    }
}

impl ToBytes for LockManFilePreHeader {}
impl ToBytes for LockManFileHeader {}
