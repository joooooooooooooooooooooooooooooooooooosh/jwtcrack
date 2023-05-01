use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::exit,
};

use clap::Parser;
use hmac::{Hmac, Mac};
use jwt::VerifyingAlgorithm;
use sha2::Sha256;

use rayon::prelude::*;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    jwt: String,

    #[arg(short, long)]
    wordlist: PathBuf,
}

fn main() {
    let args = Args::parse();
    let wordlist = BufReader::new(File::open(args.wordlist).expect("wordlist should exist"));

    wordlist.lines().par_bridge().for_each(|word| {
        let Ok(word) = word else {
            return;
        };

        let key: Hmac<Sha256> = Hmac::new_from_slice(word.as_bytes()).expect("this shouldn't fail");

        if verify(args.jwt.as_ref(), &key).is_ok() {
            println!("found secret: {word:?}");
            exit(0)
        }
    });

    println!("No secret found, try another wordlist");
}

fn verify(jwt: &str, key: &impl VerifyingAlgorithm) -> Result<(), Box<dyn Error>> {
    let mut components = jwt.split('.');
    let header = components.next().ok_or(jwt::Error::NoHeaderComponent)?;
    let claims = components.next().ok_or(jwt::Error::NoClaimsComponent)?;
    let signature = components.next().ok_or(jwt::Error::NoSignatureComponent)?;

    if key.verify(header, claims, signature)? {
        Ok(())
    } else {
        Err(jwt::Error::Format.into())
    }
}