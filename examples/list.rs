extern crate env_logger;
extern crate nfc_oath;

use nfc_oath::OathController;

fn main() {
    env_logger::init().unwrap();

    let controller = OathController::new().unwrap();
    controller.poll(None);
    let creds = controller.list();
    println!("{:?}", creds);
    controller.close();
}
