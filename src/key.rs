use secp256k1::rand::thread_rng;
use secp256k1::PublicKey;
use secp256k1::{Secp256k1, SecretKey};
use std::str::FromStr;
use web3::signing::keccak256;
use web3::types::Address;

pub trait SecretWrapper {
    fn new_key() -> (SecretKey, PublicKey);
}

pub trait PublicWrapper {
    fn from_private_key(private_key: &str) -> String;
}

impl SecretWrapper for SecretKey {
    fn new_key() -> (SecretKey, PublicKey) {
        let (secret_key, public_key) = secp256k1::generate_keypair(&mut thread_rng());

        (secret_key, public_key)
    }
}

impl PublicWrapper for PublicKey {
    fn from_private_key(private_key: &str) -> String {
        let private_key = private_key.replace("0x", "");

        let secret_key = SecretKey::from_str(private_key.as_str()).unwrap();

        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);

        let public_key = public_key.serialize_uncompressed();

        hex::encode(&public_key[1..])
    }
}

pub trait AddressWrapper {
    fn from_public_key_str(public_key: &str) -> Address;
    fn from_private_key(secret_key: &SecretKey) -> Address;
    fn from_public_key(public_key: PublicKey) -> Address;
}

impl AddressWrapper for Address {
    fn from_public_key_str(public_key: &str) -> Address {
        let public_key = "04".to_string() + &public_key.to_string();

        let public_key = PublicKey::from_str(public_key.as_str()).unwrap();

        Address::from_public_key(public_key)
    }

    fn from_private_key(secret_key: &SecretKey) -> Address {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);

        Address::from_public_key(public_key)
    }

    fn from_public_key(public_key: PublicKey) -> Address {
        let public_key = public_key.serialize_uncompressed();

        debug_assert_eq!(public_key[0], 0x04);

        let hash = keccak256(&public_key[1..]);

        Address::from_slice(&hash[12..])
    }
}

#[cfg(test)]
mod tests {

    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    use super::*;

    #[test]
    fn it_create_private_key() {
        for _ in 1..100 {
            let (secret, public_key) = SecretKey::new_key();
            let secret = secret.secret_bytes();
            let public_key = public_key.serialize_uncompressed();

            println!("{}", hex::encode(secret));
            println!("{}", hex::encode(public_key));
            let address = Address::from_public_key_str(hex::encode(&public_key[1..]).as_str());

            println!("{}", hex::encode(address));
        }
    }

    #[test]
    fn it_get_public_key_from_private_key() {
        let private_key = "7fca6f05cf07a79fbc713fddaf25b80cae85f2c1f8b8608ca9ef94e529ff6a27";

        let public_key = PublicKey::from_private_key(private_key);

        println!("{}", public_key);

        let public_key_new =  "ea7564ade543595e3195e4ddc5e5650aa29a59862929936b3b74dfeb59f86f0a0efb8308e7b9598d9e0e60977a29afe99d4a5671ab29a17c6de7ec20e2bea3d5".to_string();

        assert_eq!(public_key_new, public_key)
    }

    #[test]
    fn it_get_public_address() {
        let public_key = "358bbe04823acb656d1635e6e89311c5202de5c738b24b7be06301babbe7a3b72bc3e58abe30a7510ea253157f852ea8603d767512668f2ac06f50d9c29e760a";

        let address = Address::from_public_key_str(public_key);

        println!("address: {}", address);

        let address = hex::encode(&address);

        println!("address: {}", address);

        assert_eq!("3e94eadea4fc59bd7ea1b0f0130f01a65f07925c", address)
    }

    #[test]
    fn it_get_public_key() {
        let pbs = [
                "857a130ef6ba984dbcc9cb4987585263c8805efd17776f6543872eb836489c1787fd6d24da9aec097e1e7524ef65df264855efa8b655e4b88fd4c41d498c9f44",
                "23f50da4f508fef443b42b69077de4b1687cdf06c1eda497209dc26e2817896cb5ab99ef68fec75b724b890ca687c723c9079d3ba9e9b4edd46f222fdbe06d6a",
                "a1b31be4d58a7ddd24b135db0da56a90fb5382077ae26b250e1dc9cd6232ce2270f4c995428bc76aa78e522316e95d7834d725efc9ca754d043233af6ca90113",
                "ea7564ade543595e3195e4ddc5e5650aa29a59862929936b3b74dfeb59f86f0a0efb8308e7b9598d9e0e60977a29afe99d4a5671ab29a17c6de7ec20e2bea3d5",
                "6614d7d7bfe989295821985de0439e868b26ff05f98ae0da0ce5bccc24ea368a083b785323c9fcb405dd4c10a2c95d93312a1b2d68beb24ab4ea7c3c2f7c455b",
                "506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aaba645c0b7b58158babbfa6c6cd5a48aa7340a8749176b120e8516216787a13dc76",
            ];

        for item in pbs {
            let address = Address::from_public_key_str(item);

            println!("address {}", hex::encode(address));
        }
    }

    #[test]
    fn it_get_public_key_file() {
        let filename = "tests/res/dev_new.csv";
        // Open the file in read-only mode (ignoring errors).
        let file = File::open(filename).unwrap();
        let reader = BufReader::new(file);

        // Read the file line by line using the lines() iterator from std::io::BufRead.
        for (_, line) in reader.lines().enumerate() {
            let line = line.unwrap(); // Ignore errors.
            let mut line = line.split(",");
            let public = line.next();
            let address_eva = line.next();

            println!(
                "pub:{}, add:{}",
                public.unwrap(),
                address_eva.unwrap().trim()
            );

            let address = Address::from_public_key_str(public.unwrap().trim());
            let ad = "0x".to_string() + &hex::encode(address);
            assert_eq!(ad, address_eva.unwrap().trim());
        }
    }

    #[test]
    fn get_hash() {
        let hash = "3b6a00f152820f2e03e4b7724060f8f715fb94f03068b3ce4df5b0a5b15ee449";
        let size = hex::decode(hash).unwrap();

        println!("before :{},size: {}", hash.as_bytes().len(), size.len());
    }
}
