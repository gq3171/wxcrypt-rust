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
use std::borrow::Cow;
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
pub struct WxCrptUtil<'a> {
    token: Cow<'a, str>,
    aeskey: Cow<'a, [u8]>,
    receiveid: Cow<'a, str>,
}

impl<'a> WxCrptUtil<'a> {
    ///
    /// 初始化WxCrptUtil
    /// encodingaeskey 企业微信后台，开发者设置的EncodingAESKey,未经Base64解密
    /// 返回初始化后的WxCrptUtil类型
    pub fn new<T>(token: T, encodingaeskey: T, receiveid: T) -> WxCrptUtil<'a>
    where
        T: Into<Cow<'a, str>>,
    {
        let mut en_aeskey = encodingaeskey.into();
        en_aeskey.to_mut().push_str("=");
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let aeskey = match decode_config(en_aeskey.to_mut(), config) {
            Ok(n) => n,
            Err(e) => panic!("初始化AesKey错误:{}", e),
        };
        WxCrptUtil {
            token: token.into(),
            aeskey: Cow::from(aeskey),
            receiveid: receiveid.into(),
        }
    }

    ///
    /// 对明文进行加密.
    /// plaintext 需要加密的明文
    /// random_str 随机生成的字符串
    /// 返回加密后的字符串
    pub fn encrypt<T>(&self, random_str: T, plaintext: T) -> String
    where
        T: Into<Cow<'a, str>>,
    {
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let iv = &self.aeskey[0..16];
        let key = &self.aeskey[..];
        let mut v_bytes = random_str.into().to_mut().as_bytes().to_vec();
        let mut text_bytes = plaintext.into().to_mut().as_bytes().to_vec();
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

    ///
    ///对密文解密
    /// cipher_text 需要解密的密文
    /// 返回解密后的字符串
    /// 
    pub fn decrypt<T>(&self, cipher_text: T) -> String
    where
        T: Into<Cow<'a, str>>,
    {
        let config = base64::STANDARD.decode_allow_trailing_bits(true);
        let text_s =
            match decode_config(&urldecode(cipher_text.into().to_mut().to_string()), config) {
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
    /// plaintext 需要加密的明文
    /// 返回加密后的xml字符串
    /// 
    pub fn encrypt_msg<T>(&self, plaintext: T) -> String
    where
        T: Into<Cow<'a, str>>,
    {
        let random_str = get_random_str();
        let encrypted_xml = self.encrypt(random_str, plaintext.into().to_mut().to_string());
        let nonce = get_random_str();
        let timestamp = Local::now().timestamp();
        let signature = self.getsha1(timestamp.to_string(), nonce.clone(), encrypted_xml.clone());

        xml_create(
            encrypted_xml.clone(),
            signature,
            timestamp.to_string(),
            nonce.clone(),
        )
    }

    ///
    /// 对收到的检验消息的真实性，并且获取解密后的明文.
    /// msgSignature 签名串，对应URL参数的msg_signature
    /// timeStamp 时间戳，对应URL参数的timestamp
    /// nonce 随机串，对应URL参数的nonce
    /// postData 密文，对应POST请求的数据
    /// 返回解密后的字符串
    /// 
    pub fn decrypt_msg<T>(
        &self,
        msgsignature: T,
        timestamp: T,
        nonce: T,
        postdata: T,
    ) -> String 
    where T:Into<Cow<'a,str>> + Copy
    {
        let x: Xml = match from_reader(postdata.into().as_bytes()) {
            Ok(n) => n,
            Err(e) => panic!("xml解析错误:{}", e),
        };
        let signature = self.getsha1(timestamp.into().to_string(), nonce.into().to_string(), x.Encrypt.clone());
        if signature != msgsignature.into() {
            panic!(
                "消息解密,Sha1签名验证不通过:\n {} \n {}",
                signature, msgsignature.into()
            );
        };
        let result = self.decrypt(x.Encrypt.clone());
        result
    }

    ///
    /// 用SHA1算法生成安全签名
    /// timestamp 时间戳
    /// nonce 随机字符串
    /// encrypt 密文
    /// 返回安全签名
    pub fn getsha1<T>(&self, timestamp: T, nonce: T, encrypt: T) -> String 
    where T:Into<Cow<'a,str>>
    {
        let mut v = vec![
            self.token.to_string(),
            timestamp.into().to_mut().to_string(),
            nonce.into().to_mut().to_string(),
            urldecode(encrypt.into().to_mut().to_string()),
        ];
        v.sort();
        let str: String = v.into_iter().collect();
        let mut hasher = Sha1::new();
        hasher.input_str(&str);
        hasher.result_str()
    }

    ///
    /// msgSignature 签名串，对应URL参数的msg_signature
    /// timeStamp 时间戳，对应URL参数的timestamp
    /// nonce 随机串，对应URL参数的nonce
    /// echoStr 随机串，对应URL参数的echostr
    /// 返回解密后的验证字符串
    ///
    pub fn verifyurl<T>(
        &self,
        msgsignature: T,
        timestamp: T,
        nonce: T,
        echostr: T,
    ) -> String 
    where T: Into<Cow<'a,str>> + Copy
    {
        let signature = self.getsha1(timestamp, nonce, echostr);
        if signature != msgsignature.into().to_mut().to_string() {
            panic!("Sha1签名验证不通过:\n {} \n {}", signature, msgsignature.into());
        };
        let result = self.decrypt(echostr);
        result
    }
}

///
/// 随机生成16位字符串
///
fn get_random_str() -> String {
    let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(16).collect();
    rand_string
}
///
/// 生成4个字节的网络字节序
///
fn get_network_bytes_order(num: usize) -> [u8; 4] {
    (num as u32).to_be_bytes()
}

///
/// 生成xml消息
/// encrypt 加密后的消息密文
/// signature 安全签名
/// timestamp 时间戳
/// nonce 随机字符串
/// 返回打包后的xml字符串
///
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
