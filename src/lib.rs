#[macro_use] extern crate log;
extern crate byteorder;
extern crate chrono;
extern crate nfc;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use chrono::{DateTime, Utc};
use nfc::context;
use nfc::device;
use nfc::ffi;
use nfc::initiator;
use nfc::misc;
use std::collections::HashMap;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::mem;
use std::ptr;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }

    #[test]
    fn code_formatter_works() {
        let code = ::OathCode{digits: ::OathDigits::Six, value: 595641143, expiration: 0, steam: false };
        assert!(format!("{}", code) == "641143");
    }
    #[test]
    fn parse_tlv_works() {
        let resp = ::parse_tlv(&vec![0x76, 0x05, 0x06, 0x23, 0x80, 0xc3, 0x37, 0x90, 0x00]);
        println!("{:?}", resp);
    }
}

pub enum Tag {
    Name = 0x71,
    NameList = 0x72,
    Key = 0x73,
    Challenge = 0x74,
    Response = 0x75,
    TruncatedResponse = 0x76,
    Hotp = 0x77,
    Property = 0x78,
    Version = 0x79,
    Imf = 0x7a,
    Algorithm = 0x7b,
    Touch = 0x7c,
}

pub enum OathAlgo {
    Sha1 = 0x01,
    Sha256 = 0x02,
}

pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

pub enum Properties {
    RequireTouch = 0x02,
}

pub enum Ins {
    Put = 0x01,
    Delete = 0x02,
    SetCode = 0x03,
    Reset = 0x04,
    List = 0xa1,
    Calculate = 0xa2,
    Validate = 0xa3,
    CalculateAll = 0xa4,
    SendRemaining = 0xa5,
}

pub enum Mask {
    Algo = 0x0f,
    Type = 0xf0,
}

pub enum Sw {
    NoSpace = 0x6a84,
    CommandAborted = 0x6f00,
    MoreData = 0x61,
    InvalidInstruction = 0x6d00,
}

#[derive(Clone, Copy)]
pub enum OathDigits {
    Six = 6,
    Eight = 8,
}

pub struct OathCode {
    pub digits: OathDigits,
    pub value: u32,
    pub expiration: u32, // FIXME
    pub steam: bool,
}
pub struct OathCredential {
    pub name: String,
    pub code: Result<OathCode, String>,
    pub oath_type: OathType,
    pub touch: bool,
    pub algo: OathAlgo,
    pub hidden: bool,
    pub steam: bool,
}
pub struct OathController {
    pub context: *mut ffi::nfc_context,
    pub device: *mut ffi::nfc_device,
}

pub const INS_SELECT: u8 = 0xa4;
pub const OATH_AID: [u8; 8] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01];

pub fn tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag as u8];
    let len = value.len();
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.write_u16::<BigEndian>(len as u16).unwrap();
    }
    buf.write(value).unwrap();
    buf
}

pub fn parse_tlv(data: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut rdr = Cursor::new(data);
    let mut map = HashMap::new();
    loop {
        let tag = match rdr.read_u8() {
            Ok(tag) => tag,
            Err(_) => break,
        };
        let mut len: u16 = match rdr.read_u8() {
            Ok(len) => len as u16,
            Err(_) => break,
        };
        if len > 0x80 {
            let n_bytes = len - 0x80;
            if n_bytes == 1 {
                len = match rdr.read_u8() {
                    Ok(len) => len as u16,
                    Err(_) => break,
                };
            } else if n_bytes == 2 {
                len = match rdr.read_u16::<BigEndian>() {
                    Ok(len) => len,
                    Err(_) => break,
                };
            }
        }
        let mut dst = Vec::with_capacity(len as usize);
        unsafe {
            dst.set_len(len as usize);
        }
        match rdr.read_exact(dst.as_mut_slice()) {
            Ok(_) => (),
            Err(_) => break,
        };
        map.insert(tag, dst);
    }
    map
}

pub fn time_challenge(datetime: Option<DateTime<Utc>>) -> Vec<u8> {
    let ts = match datetime {
        Some(datetime) => datetime.timestamp() / 30,
        None => Utc::now().timestamp() / 30,
    };
    let mut buf = vec![];
    buf.write_u32::<BigEndian>(ts as u32).unwrap();
    buf
}

impl fmt::Display for OathCode {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        const STEAM_CHAR_TABLE_LEN: u32 = 26;
        const STEAM_CHAR_TABLE: [char; STEAM_CHAR_TABLE_LEN as usize] = ['2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y'];
        let mut code = self.value;
        if self.steam {
            let mut str = String::new();
            for _i in 0..5 {
                str.push(*STEAM_CHAR_TABLE.get((code % STEAM_CHAR_TABLE_LEN) as usize).unwrap());
                code /= STEAM_CHAR_TABLE_LEN;
            }
            try!(fmt.write_str(&str));
        } else {
            let code = self.value % (10 as u32).pow(self.digits as u32);
            match self.digits {
                OathDigits::Six => write!(fmt, "{:06}", code),
                OathDigits::Eight => write!(fmt, "{:08}", code),
            }.unwrap();
        }
        Ok(())
    }
}

impl OathCredential {
    pub fn new(name: &str, oath_type: OathType, touch: bool, algo: OathAlgo) -> OathCredential {
        OathCredential{name: name.to_string(), 
                       code: Err("No code calculated yet".to_string()), 
                       oath_type: oath_type, 
                       touch: touch, 
                       algo: algo, 
                       hidden: name.starts_with("_hidden:"), 
                       steam: name.starts_with("Steam:")
        }
    }
}

impl OathController {
    pub fn new() -> Result<OathController, String> {
        let mut context = context::new();

        if context.is_null() {
            return Err("Unable to initialize new NFC context!".to_string());
        }

        nfc::init(&mut context);
        
        debug!("libnfc version: {}", ::misc::version());

        let device = nfc::open(context, ptr::null());
        if device.is_null() {
            return Err("Unable to initialize new NFC device!".to_string());
        }

        initiator::init(Box::new(device));

        debug!("NFC reader: {} opened", device::get_name(device));

        device::set_property_bool(device, ffi::Enum_Unnamed1::NP_AUTO_ISO14443_4, 1);

        Ok(OathController{ context: context, device: device })
    }

    pub fn close(&self) {
        nfc::close(self.device);
    }

    pub fn poll(&self, duration: Option<Duration>) -> bool {
      let start = Instant::now();

      debug!("Polling for target...");
      let modu = ffi::nfc_modulation{nmt: ffi::nfc_modulation_type::NMT_ISO14443A, nbr: ffi::nfc_baud_rate:: NBR_106};
      unsafe {
          let mut target: ffi::nfc_target = mem::uninitialized();
          while initiator::poll_target(self.device, &modu, 1, 1, 1, &mut target) <= 0 {
              if let Some(duration) = duration {
                  if Instant::now() > (start + duration) {
                      debug!("Poll timed out");
                      return false;
                  }
              }
          }
          while initiator::select_passive_target(self.device, modu, (*target.nti.nai()).abtUid.as_mut_ptr(), (*target.nti.nai()).szUidLen, &mut target) <= 0 { }
      }
      debug!("Target detected!");
      return true;
    }

    /* https://en.wikipedia.org/wiki/Application_protocol_data_unit
    Command APDU
    Field name	Length (bytes)	Description
    CLA	1	Instruction class - indicates the type of command, e.g. interindustry or proprietary
    INS	1	Instruction code - indicates the specific command, e.g. "write data"
    P1-P2	2	Instruction parameters for the command, e.g. offset into file at which to write the data
    Lc	0, 1 or 3	Encodes the number (Nc) of bytes of command data to follow
        0 bytes denotes Nc=0
        1 byte with a value from 1 to 255 denotes Nc with the same value
        3 bytes, the first of which must be 0, denotes Nc in the range 1 to 65 535 (all three bytes may not be zero)
    Command data	Nc	Nc bytes of data
    Le	0, 1, 2 or 3	Encodes the maximum number (Ne) of response bytes expected
        0 bytes denotes Ne=0
        1 byte in the range 1 to 255 denotes that value of Ne, or 0 denotes Ne=256
        2 bytes (if Lc was present in the command) in the range 1 to 65 535 denotes Ne of that value, or two zero bytes denotes 65 536
        3 bytes (if Lc was not present in the command), the first of which must be 0, denote Ne in the same way as two-byte Le
    */
    pub fn send_apdu(&self, class: u8, instruction: u8, parameter1: u8, parameter2: u8, data: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut tx_buf = vec![];
        let nc = match data {
            Some(ref data) => data.len(),
            None => 0,
        };
        // Header
        tx_buf.push(class);
        tx_buf.push(instruction);
        tx_buf.push(parameter1);
        tx_buf.push(parameter2);
 
        // Data
        if nc > 255 {
            tx_buf.push(0);
            tx_buf.write_u16::<BigEndian>(nc as u16).unwrap();
        } else if nc > 0 {
            tx_buf.push(nc as u8);
        }
        if let Some(data) = data {
            tx_buf.write(data).unwrap();
        }

        let mut s = String::new();
        for byte in &tx_buf {
            s += &format!("{:02X} ", byte);
        }
        debug!(">> {}", s);
        
        let mut rx_buf = Vec::with_capacity(256);
        let bytes_read = initiator::transceive_bytes(self.device, tx_buf.as_ptr(), tx_buf.len(), rx_buf.as_mut_ptr(), 256, 0);
        if bytes_read < 0 {
            return Err("Error no bytes were returned".to_string());
        }

        unsafe {
            rx_buf.set_len(bytes_read as usize);
        }

        let mut s = String::new();
        for byte in &rx_buf {
            s += &format!("{:02X} ", byte);
        }
        debug!("<< {}", s);

        {
            let sw1 = match rx_buf.get((bytes_read-2) as usize) {
                Some(sw1) => sw1,
                None => return Err("Error invalid bytes were returned".to_string())
            };
            let sw2 = match rx_buf.get((bytes_read-1) as usize) {
                Some(sw2) => sw2,
                None => return Err("Error invalid bytes were returned".to_string())
            };
            if *sw1 != 0x90 || *sw2 != 0x00 {
                return Err(format!("Error {:x} {:x}", sw1, sw2));
            }
        }
        Ok(rx_buf)
    }

    pub fn calculate(&self, mut credential: OathCredential) -> OathCredential {
        // Switch to the OATH applet
        if let Err(err) = self.send_apdu(0, INS_SELECT, 0x04, 0, Some(&OATH_AID)) {
            credential.code = Err(err);
            return credential
        }

        let mut data = tlv(Tag::Name, credential.name.as_bytes());
        let datetime = Utc::now();
        let challenge = time_challenge(Some(datetime));
        data.write(&tlv(Tag::Challenge, &challenge)).unwrap();
        let resp = match self.send_apdu(0, Ins::Calculate as u8, 0, 0x01, Some(&data)) {
            Ok(resp) => resp,
            Err(err) => {
                credential.code = Err(err);
                return credential
            }
        };

        let resp = parse_tlv(&resp[0..resp.len()-2]);
        let resp = match resp.get(&(Tag::TruncatedResponse as u8)) {
            Some(resp) => resp,
            None => {
                credential.code = Err("Response tlv was invalid".to_string());
                return credential
            }
        };
        let mut rdr = Cursor::new(resp);

        let digits = match rdr.read_u8() {
            Ok(digits) => {
                let digits = match digits {
                    6 => OathDigits::Six,
                    8 => OathDigits::Eight,
                    _ => {
                        credential.code = Err("Digits can only be 6 or 8".to_owned());
                        return credential
                    }
                };
                digits
            },
            Err(err) => {
                credential.code = Err(err.to_string());
                return credential
            }
        };

        let val = match rdr.read_u32::<BigEndian>() {
            Ok(val) => val,
            Err(err) => {
                credential.code = Err(err.to_string());
                return credential
            }
        };
        let expiration = ((datetime.timestamp() + 30) / 30) * 30;

        credential.code = Ok(OathCode{digits: digits, value: val, expiration: expiration as u32, steam: credential.steam});
        credential
    }
}
