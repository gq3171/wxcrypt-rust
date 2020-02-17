extern crate aes_soft as aes;
extern crate base64;
extern crate block_modes;
extern crate byteorder;
extern crate chrono;
extern crate crypto;
extern crate rand;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_xml_rs;

use aes::Aes256;
use base64::decode_config;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use byteorder::{BigEndian, ReadBytesExt};
use chrono::prelude::*;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_xml_rs::from_reader;
use urldecode::decode as urldecode;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Debug, Deserialize)]
struct Xml {
    ToUserName: String,
    Encrypt: String,
    AgentID: String,
}

///
/// token       企业微信后台，开发者设置的token
/// aeskey      企业微信后台，开发者设置的EncodingAESKey经过Base64解密后的vec<u8>
/// receiveid   不同场景含义不同，详见文档
///
pub struct WxCrptUtil {
    token: String,
    aeskey: Vec<u8>,
    receiveid: String,
}

impl WxCrptUtil {
    ///
    /// 初始化WxCrptUtil
    /// encodingaeskey 企业微信后台，开发者设置的EncodingAESKey,未经Base64解密
    ///
    pub fn new(token: &str, encodingaeskey: &str, receiveid: &str) -> WxCrptUtil {
        let mut en_aeskey = encodingaeskey.to_string();
        en_aeskey.push_str("=");
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let aeskey = match decode_config(&en_aeskey, config) {
            Ok(n) => n,
            Err(e) => panic!("初始化AesKey错误:{}", e),
        };
        WxCrptUtil {
            token: token.to_string(),
            aeskey: aeskey,
            receiveid: receiveid.to_string(),
        }
    }

    ///
    /// 对明文进行加密.
    /// plaintext 需要加密的明文
    ///
    pub fn encrypt(&self, random_str: String, plaintext: String) -> String {
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let iv = &self.aeskey[0..16];
        let key = &self.aeskey[..];
        let mut v_bytes = random_str.as_bytes().to_vec();
        let mut text_bytes = plaintext.as_bytes().to_vec();
        let mut text_len_bytes = get_network_bytes_order(text_bytes.len()).to_vec();
        let mut receiveid_bytes = self.receiveid.as_bytes().to_vec();
        v_bytes.append(&mut text_len_bytes);
        v_bytes.append(&mut text_bytes);
        v_bytes.append(&mut receiveid_bytes);
        let cipher = match Aes256Cbc::new_var(key, iv) {
            Ok(n) => n,
            Err(e) => panic!("Aes_CBC Encrypt:{}", e),
        };

        let ciphertext = cipher.encrypt_vec(&v_bytes);
        let encode_base64_encrypted = base64::encode_config(&ciphertext, config);

        encode_base64_encrypted
    }

    pub fn decrypt(&self, cipher_text: String) -> String {
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let text_s = match decode_config(&urldecode(cipher_text.to_string()), config) {
            Ok(n) => n,
            Err(e) => panic!("decrypt:{}", e),
        };

        let iv = &self.aeskey[0..16];
        let key = &self.aeskey[..];
        let cipher = match Aes256Cbc::new_var(key, iv) {
            Ok(n) => n,
            Err(e) => panic!("Aes_CBC Decrypt:{}", e),
        };
        let decrypted_ciphertext = match cipher.decrypt_vec(&text_s[..]) {
            Ok(n) => n,
            Err(e) => panic!("{}", e),
        };

        let content = &decrypted_ciphertext[16..];
        let mut msg_slice = &content[..4];
        let msg_len = msg_slice.read_u32::<BigEndian>().unwrap();
        let msg = &content[4..(msg_len + 4) as usize];
        //let receiveid = &content[(msg_len + 4) as usize..];
        let result = String::from_utf8(msg.to_vec()).unwrap();

        result
    }

    ///
    ///将企业微信回复用户的消息加密打包.
    ///
    pub fn encrypt_msg(&self, plaintext: String) -> String {
        let random_str = get_random_str();
        let encrypted_xml = self.encrypt(random_str, plaintext);
        let nonce = get_random_str();
        let timestamp = Local::now().timestamp();
        let signature = self.getsha1(timestamp.to_string(), nonce.clone(), encrypted_xml.clone());
        
        println!("nonce:{},timestamp:{},signature:{}",nonce,timestamp,signature);
        xml_create(
            encrypted_xml.clone(),
            signature,
            timestamp.to_string(),
            nonce.clone(),
        )
    }

    pub fn decrypt_msg(
        &self,
        msgsignature: String,
        timestamp: String,
        nonce: String,
        postdata: String,
    ) -> String {
        let x: Xml = match from_reader(postdata.as_bytes()){
            Ok(n) => n,
            Err(e) => panic!("xml解析错误:{}",e),
        };
        let signature = self.getsha1(timestamp.to_string(), nonce.clone(), x.Encrypt.clone());
        if signature != msgsignature {
            panic!(
                "消息解密,Sha1签名验证不通过:\n {} \n {}",
                signature, msgsignature
            );
        };
        let result = self.decrypt(x.Encrypt.clone());
        result
    }

    pub fn getsha1(&self, timestamp: String, nonce: String, encrypt: String) -> String {
        let mut v = vec![
            self.token.clone(),
            timestamp,
            nonce,
            urldecode(encrypt.to_string()),
        ];
        v.sort();
        let str: String = v.into_iter().collect();
        let mut hasher = Sha1::new();
        hasher.input_str(&str);
        hasher.result_str()
    }

    pub fn verifyurl(
        &self,
        msgsignature: String,
        timestamp: String,
        nonce: String,
        echostr: String,
    ) -> String {
        let signature = self.getsha1(timestamp, nonce, echostr.clone());
        if signature != msgsignature {
            panic!("Sha1签名验证不通过:\n {} \n {}", signature, msgsignature);
        };
        let result = self.decrypt(echostr.clone());
        result
    }
}

fn get_random_str() -> String {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();
    rand_string
}

fn get_network_bytes_order(num: usize) -> [u8; 4] {
    (num as u32).to_be_bytes()
}

pub fn xml_create(encrypt: String, signaure: String, timestamp: String, nonce: String) -> String {
    let xml_str = format!("<xml>\n<Encrypt><![CDATA[{}]]></Encrypt>\n<MsgSignature><![CDATA[{}]]></MsgSignature>\n<TimeStamp>{}</TimeStamp>\n<Nonce><![CDATA[{}]]></Nonce>\n</xml>",encrypt,signaure,timestamp,nonce);
    xml_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_create() {
        let s = super::xml_create(
            "123".to_string(),
            "345".to_string(),
            "789".to_string(),
            "012".to_string(),
        );
        let c_str = "<xml>\n<Encrypt><![CDATA[123]]></Encrypt>\n<MsgSignature><![CDATA[345]]></MsgSignature>\n<TimeStamp>789</TimeStamp>\n<Nonce><![CDATA[012]]></Nonce>\n</xml>";
        assert_eq!(s, c_str);
    }
}
