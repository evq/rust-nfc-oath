extern crate nfc_oath;

use nfc_oath::{OathController, OathCredential, OathType, OathAlgo};

fn main() {
    let mut controller = OathController::new(None).unwrap();
    controller.poll();
    let mut cred = OathCredential::new("FidesmoOTPTutorial:tutorial@fidesmo.com", OathType::TOTP, false, OathAlgo::SHA256);
    cred = controller.calculate(cred);
    println!("{}", cred.code.unwrap());
    controller.close();
}
