pub mod jwt;
pub mod key;
pub mod mnid;

#[cfg(test)]
mod test_super {
    use crate::key::AddressWrapper;
    use secp256k1::SecretKey;
    use std::str::FromStr;
    use web3::ethabi::Address;

    #[tokio::test]
    async fn test_get_chain_id() -> web3::Result<()> {
        let transport = web3::transports::Http::new("http://localhost:2020")?;
        let web3 = web3::Web3::new(transport);
        let chainid = web3.eth().chain_id().await?;
        println!("chainid:{}", chainid);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_price() -> web3::Result<()> {
        let transport = web3::transports::Http::new("http://localhost:2020")?;
        let web3 = web3::Web3::new(transport);
        let gas_price = web3.eth().gas_price().await?;
        println!("gas_price:{}", gas_price);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_number() -> web3::Result<()> {
        let transport = web3::transports::Http::new("http://localhost:2020")?;
        let web3 = web3::Web3::new(transport);
        let block_number = web3.eth().block_number().await?;
        println!("block_number:{}", block_number);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_nounce_from_address() -> web3::Result<()> {
        let pk = "0x6def68041b8e7de549a549f3daa0573628b90f74871945fbe72940f7e7745b1a";
        let pk = pk.replace("0x", "");
        let secret = SecretKey::from_str(pk.as_str()).unwrap();

        let address = Address::from_private_key(&secret);

        let transport = web3::transports::Http::new("http://localhost:2020")?;
        let web3 = web3::Web3::new(transport);
        let block_number = web3.eth().transaction_count(address, None).await?;

        println!("block_number:{}", block_number);
        Ok(())
    }
}
