use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::exit,
};

use clap::Parser;
use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, FromBase64, VerifyingAlgorithm};
use sha2::{Sha256, Sha384, Sha512};

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

    let (algorithm, header, claims, signature) = split_jwt(&args.jwt).expect("bad jwt");

    wordlist.lines().par_bridge().for_each(|word| {
        let Ok(word) = word else {
            return;
        };

        let key: Box<dyn VerifyingAlgorithm> = match algorithm {
            AlgorithmType::Hs256 => Box::new(
                Hmac::<Sha256>::new_from_slice(word.as_bytes()).expect("this shouldn't fail"),
            ),
            AlgorithmType::Hs384 => Box::new(
                Hmac::<Sha384>::new_from_slice(word.as_bytes()).expect("this shouldn't fail"),
            ),
            AlgorithmType::Hs512 => Box::new(
                Hmac::<Sha512>::new_from_slice(word.as_bytes()).expect("this shouldn't fail"),
            ),
            AlgorithmType::None => {
                println!("None type specified - nothing to crack");
                exit(0);
            },
            _ => {
                eprintln!("Currently only deal with HS{{256, 384, 512}} algorithms -- if you want to implement other ones, please submit a PR");
                exit(1);
            }
        };

        if key.verify(header, claims, signature).unwrap_or(false) {
            println!("found secret: {word:?}");
            exit(0)
        }
    });

    println!("No secret found, try another wordlist");
}

fn split_jwt(jwt: &str) -> Result<(AlgorithmType, &str, &str, &str), jwt::Error> {
    let mut components = jwt.split('.');
    let header = components.next().ok_or(jwt::Error::NoHeaderComponent)?;
    let claims = components.next().ok_or(jwt::Error::NoClaimsComponent)?;
    let signature = components.next().ok_or(jwt::Error::NoSignatureComponent)?;

    let algorithm = jwt::Header::from_base64(header)?.algorithm;

    Ok((algorithm, header, claims, signature))
}
