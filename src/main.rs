use httpsig::prelude::{message_component, HttpSignatureBase, HttpSignatureParams};
use rsa::{pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey}, pkcs8::LineEnding, traits::PaddingScheme, Pkcs1v15Encrypt, RsaPrivateKey};

fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;

    let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let pub_key = priv_key.to_public_key();

    dbg!(priv_key.to_pkcs1_pem(LineEnding::default()).unwrap());
    dbg!(&pub_key.to_pkcs1_pem(LineEnding::default()).unwrap());

    let signature_base = generate_canonical_request("GET", "/hello");

    dbg!(&signature_base);

    let signature = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &signature_base).unwrap();

    dbg!(signature);

}

const SIGNATURE_PARAMS: &str =
    r##"("@path" "@method");alg=RSA_V1_5_SHA256;keyid="test-key-ed25519""##;


pub fn generate_canonical_request(
    method: &str,
    path: &str,
) -> Vec<u8> {
    let path_component =
        message_component::HttpMessageComponent::try_from(format!(r#""@path": {path}"#,).as_str())
            .unwrap();
    let method_component = message_component::HttpMessageComponent::try_from(
        format!(r#""@method": {method}"#,).as_str(),
    )
    .unwrap();

    let signature_params = HttpSignatureParams::try_from(SIGNATURE_PARAMS).unwrap();
    let component_lines = [path_component, method_component];

    HttpSignatureBase::try_new(&component_lines, &signature_params)
        .unwrap()
        .as_bytes()
}
