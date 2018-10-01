extern crate nfc_oath;

use nfc_oath::{OathController, OathCredential, OathType, OathAlgo};

fn main() {
    let controller = OathController::new().unwrap();
    controller.poll(None);
    let mut cred = OathCredential::new("FidesmoOTPTutorial:tutorial@fidesmo.com", OathType::Totp, false, OathAlgo::Sha256);
    cred = controller.calculate(cred);
    println!("{}", cred.code.unwrap());
    controller.close();
}
