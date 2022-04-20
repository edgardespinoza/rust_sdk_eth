use base58::{FromBase58, ToBase58};
use sha3::{Digest, Sha3_256};

#[derive(Default)]
pub struct Mnid {
    address: String,
    network: String,
}

impl Mnid {
    pub fn decode(&mut self, code: &str) {
        let data = code.from_base58().unwrap();
        let net_length = data.len() - 24;
        let version = data[0];
        let network = &data[1..net_length];
        let address = &data[net_length..20 + net_length];
        let check = &data[net_length + 20..data.len()];

        let compare = self.checksum(version, network, address);

        if compare != check {
            panic!("MNID_INCORRECT_FORMAT {}", code);
        }
        self.address = "0x".to_string() + &hex::encode(address);
        self.network = "0x".to_string() + &hex::encode(network);
    }

    fn checksum(&self, version: u8, network: &[u8], address: &[u8]) -> Vec<u8> {
        let mut check = Vec::new();
        check.push(version);
        check.append(&mut network.clone().to_vec());
        check.append(&mut address.clone().to_vec());

        let mut hasher = Sha3_256::new();
        hasher.update(check.as_slice());
        let out = hasher.finalize();

        out[0..4].to_vec()
    }

    pub fn encode(&self) -> String {
        let network = self.network.replace("0x", "");

        let address = self.address.replace("0x", "");

        let version = 1;
        let mut network = hex::decode(network).unwrap();
        let mut address = hex::decode(address).unwrap();
        let mut check = self.checksum(version, network.as_slice(), address.as_slice());

        let mut out = Vec::new();

        out.push(version);
        out.append(&mut network);
        out.append(&mut address);
        out.append(&mut check);

        out.to_base58()
    }
}

#[cfg(test)]
mod test_super {
    use super::*;

    #[test]
    fn test_decode_mnid() {
        let code = "cwMLAxfPPDDogt921kborpNeoQJuoeDegDp4y";
        let mut mn = Mnid::default();

        mn.decode(code);

        assert_eq!("0x5d83e34f69540dd78e1f5541e45d0ff15645edee", mn.address);
        assert_eq!("0x09e551", mn.network);
    }

    #[test]
    fn test_encode_mnid() {
        let mn = Mnid {
            address: "0x5d83e34f69540dd78e1f5541e45d0ff15645edee".to_string(),
            network: "0x09e551".to_string(),
        };

        let mnid = mn.encode();

        assert_eq!("cwMLAxfPPDDogt921kborpNeoQJuoeDegDp4y", mnid);
    }
}
