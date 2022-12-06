use aes::cipher::{generic_array::typenum::U16, generic_array::GenericArray};
use aes::Aes256;
use cbc_mac::{CbcMac, Mac};
use des::Des;
use hex_literal::hex;

type CbcMacAes = CbcMac<Aes256>;

pub fn cbc_mac_aes(data: &str, key: &str) -> GenericArray<u8, U16> {
    let key_vec = hex::decode(key).unwrap();
    let data_vec = hex::decode(data).unwrap();

    let mut mac = CbcMacAes::new_from_slice(&key_vec).unwrap();

    for i in (0..data_vec.len()).step_by(8) {
        mac.update(&data_vec[i..i + 8]);
    }

    let result = mac.finalize();
    result.into_bytes()
}

type Daa = CbcMac<Des>;

pub fn des_example() {
    // test from FIPS 113
    let key = hex!("0123456789ABCDEF");
    println!("{:?}", key);
    let mut mac = Daa::new_from_slice(&key).unwrap();
    mac.update(b"7654321 Now is the time for ");
    let correct = hex!("F1D30F6849312CA4");
    mac.verify_slice(&correct).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        des_example();
    }

    #[test]
    fn it_works() {
        des_example();
        cbc_mac_aes("4D4143732061726520766572792075736566756C20696E2063727970746F677261706879212020202020202020202020", "8000000000000000000000000000000000000000000000000000000000000001");
    }
}
