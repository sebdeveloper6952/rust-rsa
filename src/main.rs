use num_bigint::{BigUint, ToBigUint};
use primal::StreamingSieve;
use rand::Rng;
use std::collections::HashMap;
use std::io::{self, Write};

/// Representation of a public key.
///
/// A public key is composed of "n", the modulus used in the mathematical
/// operations and "e", the exponent used.
#[derive(Debug)]
struct PubKey {
    n: BigUint,
    e: BigUint,
}

impl PubKey {
    fn new(n: BigUint, e: BigUint) -> PubKey {
        PubKey { n, e }
    }
}

/// Representation of a Key Pair.
///
/// A key pair is composed of a public key and a private key.
#[derive(Debug)]
struct KeyPair {
    pubkey: PubKey,
    privkey: BigUint,
}

impl KeyPair {
    fn new(pubkey: PubKey, privkey: BigUint) -> KeyPair {
        KeyPair { pubkey, privkey }
    }
}

/// Representation of a digital signature.alloc
///
/// A digital signature is composed of a cipher text and the
/// original plain text corresponding to the cipher text.
///
/// To verify the signature, an entity deciphers the signature
/// using the public key of the supposed owner of the signature,
/// if the deciphered text is the same as the message in the
/// signature, then the Digital Signature is verified.
#[derive(Debug)]
struct Signature {
    signature: Vec<BigUint>,
    message: String,
}

impl Signature {
    fn new(signature: Vec<BigUint>, message: String) -> Signature {
        Signature { signature, message }
    }
}

fn print_menu() {
    println!("********************* Rust Rsa *********************");
    println!("* 1. Creación de llaves.");
    println!("* 2. Cifrar mensaje.");
    println!("* 3. Descifrar mensajes.");
    println!("* 4. Firma digital.");
    println!("* 5. Verificar firma.");
    println!("* 6. Salir.");
    println!("****************************************************");
}

/// Creates a new keypair.
///
/// Pseudo-randomly, prime numbers are choosed as the components
/// of the keypair.
fn create_keypair() -> KeyPair {
    let p: BigUint = gen_prime();
    let q: BigUint = gen_prime();
    let mut n = (&p * &q).to_biguint().unwrap();
    let mut e = 3.to_biguint().unwrap();
    let mut phi = (&p - 1 as u32) * (&q - 1 as u32);
    let one = 1.to_biguint().unwrap();
    let mut d = 1 as u32 + (2 as u32 * &phi) / &e;
    // compute e, coprime to phi
    while (&d * &e) != (1 as u32 + 2 as u32 * &phi) {
        while &e < &phi {
            if gcd(&e, &phi) == one {
                break;
            } else {
                e += &one;
            }
        }
        let p: BigUint = gen_prime();
        let q: BigUint = gen_prime();
        n = (&p * &q).to_biguint().unwrap();
        e = 3.to_biguint().unwrap();
        phi = (&p - 1 as u32) * (&q - 1 as u32);
        d = 1 as u32 + (2 as u32 * &phi) / &e;
    }

    KeyPair::new(PubKey::new(n, e), d)
}

/// Given a message and a public key, produce the cipher text
/// of the message.
fn cipher(msg: &String, pubkey: &PubKey) -> Vec<BigUint> {
    let bytes = msg.as_bytes();
    let mut cipher: Vec<BigUint> = Vec::new();
    for byte in bytes {
        let big_byte: BigUint = byte.to_biguint().unwrap();
        let encrypted = big_byte.modpow(&pubkey.e, &pubkey.n);
        cipher.push(encrypted);
    }

    cipher
}

/// Given a cipher text and and a keypair, decipher the cipher
/// text using the keypair private key.
fn decipher(cipher: &Vec<BigUint>, keypair: &KeyPair) -> String {
    let mut bytes: Vec<u8> = Vec::new();
    for bignum in cipher {
        let dec = bignum.modpow(&keypair.privkey, &keypair.pubkey.n);
        let dec_bytes = dec.to_bytes_be();
        bytes.push(*dec_bytes.first().unwrap());
    }

    String::from_utf8(bytes).unwrap()
}

/// Cipher a message using the private key of a keypair.
///
/// Can be used to send messages to other entities, and
/// those other entities can be sure that the messages
/// are legitimately sent by the original entity.
fn sign_msg(msg: &String, keypair: &KeyPair) -> Vec<BigUint> {
    let bytes = msg.as_bytes();
    let mut cipher: Vec<BigUint> = Vec::new();
    for byte in bytes {
        let big_byte: BigUint = byte.to_biguint().unwrap();
        let encrypted = big_byte.modpow(&keypair.privkey, &keypair.pubkey.n);
        cipher.push(encrypted);
    }

    cipher
}

/// Decipher a message using the public key of keypair K.
/// If the message is deciphered correctly, that means that the
/// message was ciphered with the private key of keypair K.
///
/// Can be used to verify that a message was produced by a
/// specific entity, the entity that holds the private key of
/// key pair K.
fn verify_signature(signature: &Signature, pubkey: &PubKey) -> bool {
    let mut bytes: Vec<u8> = Vec::new();
    for bignum in &signature.signature {
        let dec = bignum.modpow(&pubkey.e, &pubkey.n);
        let dec_bytes = dec.to_bytes_be();
        bytes.push(*dec_bytes.first().unwrap());
    }

    match String::from_utf8(bytes) {
        Ok(dec) => dec == signature.message,
        _ => false,
    }
}

/**
 * Euclidean algorithm for greatest common divisor.
 */
fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    let one = 1.to_biguint().unwrap();
    loop {
        let temp = &a % &b;
        if temp < one {
            break;
        }
        a = b.clone();
        b = temp.clone();
    }
    return b;
}

/**
 * Generate random prime number.
 */
fn gen_prime() -> BigUint {
    let mut rng = rand::thread_rng();
    StreamingSieve::nth_prime(rng.gen_range(1000..10000))
        .to_biguint()
        .unwrap()
}

fn main() {
    // store keys
    let mut keys: HashMap<String, KeyPair> = HashMap::new();
    // store ciphered messages
    let mut pub_msgs: HashMap<String, Vec<Vec<BigUint>>> = HashMap::new();
    let mut signatures: Vec<Signature> = Vec::new();
    // print menu and loop
    print_menu();
    loop {
        println!("-----------------------------------------------------------------------------------------------");
        // ask for option
        let mut input_buffer = String::new();
        print!("Introduce la opción deseada: ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut input_buffer).unwrap();
        input_buffer.retain(|a| a != '\n');
        // process choice
        if input_buffer == "1" {
            let mut name = String::new();
            print!("Introduce un nombre para almacenar la llave: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            name.retain(|a| a != '\n');
            let keyp = create_keypair();
            println!("Esta es la nueva llave: {:?}", keyp);
            println!("La nueva llave ha sido almacenada.");
            keys.insert(name, keyp);
        } else if input_buffer == "2" {
            let mut msg = String::new();
            let mut name = String::new();
            print!("Introduce el mensaje a cifrar: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut msg).unwrap();
            msg.retain(|a| a != '\n');
            print!("Introduce el nombre de la llave para cifrar: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            name.retain(|a| a != '\n');
            if !keys.contains_key(&name) {
                println!("No existe una llave con ese nombre.");
                continue;
            }
            println!("El mensaje ha sido cifrado con la llave PÚBLICA que has especificado y almacenado para ser descifrado.");
            let ciphered = cipher(&msg, &keys[&name].pubkey);
            if !pub_msgs.contains_key(&name) {
                pub_msgs.insert(name.clone(), Vec::new());
            }
            pub_msgs.get_mut(&name).unwrap().push(ciphered);
        } else if input_buffer == "3" {
            let mut name = String::new();
            print!("Introduce el nombre de la llave para descifrar sus mensajes: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            name.retain(|a| a != '\n');
            if !keys.contains_key(&name) {
                println!("No existe una llave con ese nombre.");
                continue;
            }
            println!("***** Mensajes para {} *****", name);
            for message in &pub_msgs[&name] {
                println!("Mensaje Encriptado:    {:?}", message);
                println!(
                    "Mensaje Desencriptado: {:?}",
                    decipher(message, &keys[&name])
                );
            }
            println!("*******************************");
        } else if input_buffer == "4" {
            let mut msg = String::new();
            let mut name = String::new();
            print!("Introduce el mensaje a cifrar: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut msg).unwrap();
            msg.retain(|a| a != '\n');
            print!("Introduce el nombre de la llave para cifrar: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            name.retain(|a| a != '\n');
            if !keys.contains_key(&name) {
                println!("No existe una llave con ese nombre.");
                continue;
            }
            println!("El mensaje ha sido cifrado con la llave PRIVADA especificada y almacenado para su verificación.");
            let ciphered = sign_msg(&msg, &keys[&name]);
            let signature = Signature::new(ciphered, msg);
            signatures.push(signature);
        } else if input_buffer == "5" {
            let mut name = String::new();
            print!("Introduce el nombre de la llave PUBLICA para verificar mensajes: ");
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut name).unwrap();
            name.retain(|a| a != '\n');
            if !keys.contains_key(&name) {
                println!("No existe una llave con ese nombre.");
                continue;
            }
            let pubkey = &keys[&name].pubkey;
            println!("\n********** Lista de Mensajes Firmados **********");
            for sig in &signatures {
                println!(
                    "Mensaje: {:?} | Firmado por {}? => {}",
                    sig.message,
                    name,
                    verify_signature(sig, pubkey)
                );
            }
            println!("**************************************************");
        } else if input_buffer == "6" {
            println!("adios...");
            break;
        } else {
            println!("Opción no reconocida.");
        }
    }
}
