mod crypto;
mod enums;
mod header;
mod interaction;

use crate::enums::{HashAlgorithm, LockMode};
use crate::header::{LockManFileHeader, LockManFilePreHeader, ToBytes};
use aes_gcm;
use aes_gcm::aead::OsRng;
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Nonce};
use bincode::config::Configuration;
use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use env_logger::{Builder, WriteStyle};
use log::{Level, debug, error, trace};
use pbkdf2::pbkdf2_hmac;
use sha2::digest::KeyInit;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use std::fs;
use std::io::{Read, Seek, Write};

#[derive(Debug, Parser)]
#[command(name = "lockman")]
#[command(about="A simple lock manager CLI", long_about=None)]
struct CliArgs {
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    verbose: Verbosity,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(
        name = "lock",
        arg_required_else_help = true,
        about = "Locks a file using an encryption key"
    )]
    Lock {
        #[arg(value_name = "FILE", help = "The file to lock")]
        file: String,
        #[arg(
            value_name = "PASSWORD",
            help = "The password to lock the file with",
            required = true
        )]
        password: String,
    },
    #[command(
        name = "unlock",
        arg_required_else_help = true,
        about = "Unlocks a file using an encryption key"
    )]
    Unlock {
        #[arg(value_name = "FILE", help = "The file to unlock")]
        file: String,
        #[arg(
            value_name = "PASSWORD",
            help = "The password to unlock the file with",
            required = true
        )]
        password: String,
    },
}

fn derive_key_from_password(
    hash_algo: HashAlgorithm,
    password: &str,
    salt: &[u8],
    rounds: u32,
) -> Vec<u8> {
    let mut key = vec![
        0u8;
        match hash_algo {
            HashAlgorithm::Sha224 => 28,
            HashAlgorithm::Sha512_224 => 28,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512_256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    ];

    let rounds = if rounds == 0 { 310_000 } else { rounds };
    match hash_algo {
        HashAlgorithm::Sha224 => pbkdf2_hmac::<Sha224>(password.as_bytes(), salt, rounds, &mut key),
        HashAlgorithm::Sha512_224 => {
            pbkdf2_hmac::<Sha512_224>(password.as_bytes(), salt, rounds, &mut key)
        }
        HashAlgorithm::Sha256 => pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, rounds, &mut key),
        HashAlgorithm::Sha512_256 => {
            pbkdf2_hmac::<Sha512_256>(password.as_bytes(), salt, rounds, &mut key)
        }
        HashAlgorithm::Sha384 => pbkdf2_hmac::<Sha384>(password.as_bytes(), salt, rounds, &mut key),
        HashAlgorithm::Sha512 => pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, rounds, &mut key),
    }
    key
}

fn lock_file(file: String, password: String) -> Result<bool, String> {
    debug!("Checking source file if it exists and is accessible");
    let source_file_metadata = fs::metadata(&file);
    if !source_file_metadata.is_ok() {
        return Err(format!(
            "Source file {} does not exist or cannot be accessed",
            file
        ));
    }

    debug!("Checking if the source file is a directory");
    let source_file_metadata = source_file_metadata.unwrap();
    if source_file_metadata.is_dir() {
        return Err("Directories cannot be encrypted with LockMan".into());
    }

    // Target file should be the same name as the source file with a .lockman extension
    debug!("Generating target file name and checking if it exists");
    let target_file = format!("{}.lockman", file);
    let target_file_exists = fs::exists(&target_file).expect("Can't check if the lock file exist");

    // Ask for overwriting if the target file exists
    if target_file_exists
        && !interaction::ask_response(
            format!(
                "{} already exists, do you want to overwrite it? (y/N): ",
                target_file
            ),
            format!("Lock file '{}' already exists, aborting.", target_file).into(),
        )
    {
        debug!("User chose not to overwrite the lock file");
        return Ok(false);
    }

    debug!("Trying to open source file stream...");
    let mut file_stream = fs::File::open(&file).expect("Can't open the source file");

    debug!("Trying to create lock file stream...");
    let mut target_file_stream =
        fs::File::create(&target_file).expect("Can't create the lock file");

    let source_file_size: u64 = file_stream.metadata().unwrap().len();
    let block_size: u32 = 1024 * 16;
    let salt_size = crypto::salt::recommend_salt_size(HashAlgorithm::Sha256);
    let salt = crypto::salt::generate_salt(salt_size);
    debug!("Block size: {}", block_size);
    debug!("Salt size: {}", salt_size);
    debug!("Source file size: {} bytes", source_file_size);

    let file_header: LockManFileHeader = LockManFileHeader {
        key_iterations: 310_000,
        block_size,
        block_count: (source_file_size as f64 / block_size as f64).ceil() as u64,
        lock_mode: LockMode::Aes256Gcm,
        used_salt_size: salt_size,
        salt,
    };

    debug!("Encoding the file header");
    let file_header_bytes = file_header.to_bytes().expect("Can't encode the header");

    debug!("Encoding the pre-header");
    let file_pre_header: LockManFilePreHeader =
        LockManFilePreHeader::new(1, file_header_bytes.len() as u32);

    let pre_header_bytes = file_pre_header
        .to_bytes()
        .expect("Can't encode the pre-header");

    debug!("Writing the pre-header and the header");
    target_file_stream
        .write_all(&pre_header_bytes)
        .expect("Can't write the pre-header");

    target_file_stream
        .write_all(&file_header_bytes)
        .expect("Can't write the header");

    let derived_key = derive_key_from_password(
        HashAlgorithm::Sha256,
        &password,
        &salt[0..salt_size as usize],
        file_header.key_iterations,
    );
    let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();

    let mut written_block_count = 0;
    let mut buffer = vec![0u8; block_size as usize];
    while written_block_count < file_header.block_count {
        trace!(
            "Reading the next block (block index: {}, cursor: {})",
            written_block_count,
            file_stream.stream_position().unwrap()
        );

        // Read the current block
        let read_size = file_stream.read(&mut buffer).expect("Can't read the file");

        if read_size == 0 {
            debug!("No more bytes to read");
            debug!(
                "Flushing lock file stream and breaking the loop on block index: {}",
                written_block_count
            );
            target_file_stream
                .flush()
                .expect("Can't flush the encrypted file");
            break;
        }

        if read_size < block_size as usize {
            buffer.resize(read_size, 0);
        }

        // Encrypt raw contents
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        trace!("Generated nonce: {:?} (size: {})", nonce, nonce.len());
        cipher
            .encrypt_in_place(&nonce, b"", &mut buffer)
            .expect("Failed to encrypt the block");

        // Write nonce first
        target_file_stream
            .write_all(&nonce)
            .expect("Can't write the nonce");

        // Write the encrypted block
        target_file_stream
            .write_all(&mut buffer)
            .expect("Can't write the encrypted file");

        // Trim the buffer to get rid of the auth tag (16 bytes)
        buffer.resize(file_header.block_size as usize, 0);

        trace!(
            "Wrote encrypted block (nonce size: {}, block size: {}, block index: {}, cursor: {})",
            nonce.len(),
            buffer.len(),
            written_block_count,
            target_file_stream.stream_position().unwrap()
        );

        // Increment the written block count
        written_block_count += 1;

        // Flush the stream every 1024 blocks or first block if we only have 1 block
        if written_block_count % 1024 == 0 || file_header.block_count == written_block_count {
            debug!(
                "{} blocks written, flushing the stream",
                written_block_count
            );
            target_file_stream
                .flush()
                .expect("Can't flush the encrypted file");
        }
    }

    // Inform the user about the result
    println!("File '{}' locked successfully", file);

    // Ask if the user wants to delete the raw file
    if interaction::ask_response(
        "Do you want to delete the source file? (y/N): ".into(),
        None,
    ) {
        debug!("Deleting the source file");
        fs::remove_file(&file).expect("Can't delete the source file");
    }

    Ok(true)
}

fn unlock_file(file: String, password: String) -> Result<bool, String> {
    // Check if the file has the .lockman extension
    if !file.ends_with(".lockman") {
        return Err(format!(
            "File '{}' does not have the .lockman extension",
            file
        ));
    }

    // Check if the locked file exists
    let locked_file_exists = fs::exists(&file).expect("Can't check if the locked file exist");
    if !locked_file_exists {
        return Err(format!("Lock file '{}' does not exist", file));
    }

    // Target file should be the name without the .lockman extension
    let target_file = file.trim_end_matches(".lockman");
    let target_file_exists =
        fs::exists(&target_file).expect("Can't check if the target file exist");

    // Ask for overwriting
    if target_file_exists {
        if !interaction::ask_response(
            format!(
                "{} already exists, do you want to overwrite it? (y/N): ",
                target_file
            ),
            format!("Target file '{}' already exists, aborting.", target_file).into(),
        ) {
            debug!("User chose not to overwrite the target file");
            return Ok(false);
        }
    }

    let mut file_stream = fs::File::open(&file).expect("Can't open the lock file");
    let mut target_file_stream =
        fs::File::create(&target_file).expect("Can't create the target file");

    let mut buffer = vec![0u8; size_of::<LockManFilePreHeader>()];
    file_stream
        .read_exact(&mut buffer)
        .expect("Can't read the pre-header");
    let (file_pre_header, _) = bincode::decode_from_slice::<LockManFilePreHeader, Configuration>(
        &mut buffer,
        bincode::config::standard(),
    )
    .expect("Can't decode the pre-header");
    debug!("File pre-header: {:?}", file_pre_header);
    trace!(
        "File pre-header size: {}",
        size_of::<LockManFilePreHeader>()
    );
    trace!("Cursor: {}", file_stream.stream_position().unwrap());

    let mut buffer = vec![0u8; file_pre_header.header_size as usize];
    file_stream
        .read_exact(&mut buffer)
        .expect("Can't read the header");
    let (file_header, _) = bincode::decode_from_slice::<LockManFileHeader, Configuration>(
        &mut buffer,
        bincode::config::standard(),
    )
    .expect("Can't decode the header");
    debug!("File header: {:?}", file_header);
    trace!("File header size: {}", size_of::<LockManFileHeader>());
    trace!("Cursor: {}", file_stream.stream_position().unwrap());

    let derived_key = derive_key_from_password(
        HashAlgorithm::Sha256,
        &password,
        &file_header.salt[0..file_header.used_salt_size as usize],
        file_header.key_iterations,
    );
    let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();

    let mut read_block_count = 0;
    while read_block_count < file_header.block_count {
        // Get nonce for this block
        trace!(
            "Reading the nonce (block index: {}, block size: {}, cursor: {})",
            read_block_count,
            file_header.block_size + 16,
            file_stream.stream_position().unwrap(),
        );
        let mut nonce = [0u8; 12];
        file_stream.read(&mut nonce).expect("Can't read the nonce");
        let nonce = Nonce::from_mut_slice(&mut nonce);

        // Read the current block
        trace!(
            "Reading the next block (block index: {}, block size: {}, cursor: {})",
            read_block_count,
            file_header.block_size + 16,
            file_stream.stream_position().unwrap(),
        );
        let mut buffer = vec![0u8; (file_header.block_size + 16) as usize];
        let read_size = file_stream.read(&mut buffer).expect("Can't read the file");

        if read_size == 0 {
            println!("Didn't read any bytes");
            break;
        }

        if read_size < (file_header.block_size + 16) as usize {
            trace!("Read less than the block size, resizing the buffer");
            buffer.resize(read_size, 0);
        }

        // Decrypt this block
        if let Err(e) = cipher.decrypt_in_place(&nonce, b"", &mut buffer) {
            if read_block_count == 0 {
                // Delete the target file
                fs::remove_file(&target_file).expect("Can't delete the target file");
                return Err("Wrong password or malformed contents.".into());
            }

            return Err(format!(
                "Error decrypting block index {}: {}",
                read_block_count, e
            ));
        }

        // Write the decrypted block
        target_file_stream
            .write_all(&mut buffer[0..read_size - 16])
            .expect("Can't write to target file");

        // Increment read block count
        read_block_count += 1;

        // Flush the stream every 1024 blocks or first block if we only have 1 block
        if read_block_count % 1024 == 0 || file_header.block_count == read_block_count {
            debug!("{} blocks written, flushing the stream", read_block_count);
            target_file_stream
                .flush()
                .expect("Can't flush the target file");
        }
    }

    println!("File '{}' unlocked successfully", file);

    // Ask if the user wants to delete the decrypted lock file
    if interaction::ask_response(
        "Do you want to delete the locked file? (y/N): ".into(),
        None,
    ) {
        debug!("Deleting the lock file");
        fs::remove_file(&file).expect("Can't delete the lock file");
    }

    Ok(true)
}

fn setup_logger(verbosity: Verbosity) {
    let level = verbosity.log_level().unwrap_or(Level::Warn);
    let level_filter = match level {
        Level::Error => log::LevelFilter::Error,
        Level::Warn => log::LevelFilter::Warn,
        Level::Info => log::LevelFilter::Info,
        Level::Debug => log::LevelFilter::Debug,
        Level::Trace => log::LevelFilter::Trace,
    };

    Builder::from_default_env()
        .write_style(WriteStyle::Always)
        .filter(None, level_filter)
        .format(|buf, record| writeln!(buf, "[{}] - {}", record.level(), record.args()))
        .init();
}

// A function to handle the main logic returning a Result
fn run(args: CliArgs) -> Result<(), String> {
    match args.command {
        Commands::Lock { file, password } => {
            lock_file(file, password)?;
        }
        Commands::Unlock { file, password } => {
            unlock_file(file, password)?;
        }
    }

    Ok(())
}

fn main() {
    let args = CliArgs::parse();
    setup_logger(args.verbose);

    // Using Result for cleaner error handling
    if let Err(e) = run(args) {
        error!("{}", e);
        std::process::exit(1);
    }
}
