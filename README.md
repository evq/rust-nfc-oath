# rust-nfc-oath

A rust library for generating OTP codes using a hardware token and libnfc
compatible reader.

## Status

This has been tested for generating TOTP codes with the Yubikey NEO and Fidesmo Card.
Management features are not implemented, the intended use case is
an embedded reader which generates codes from a pre-provisioned credential
with a known name, such as an nfc door reader.

## See Also

Most of this code derives from the official Yubico code for OTP generation:
https://github.com/Yubico/yubikey-manager/blob/master/ykman/oath.py

The Fidesmo android TOTP NFC tutorial was also consulted and is the source for
the test credential used in the included example:
https://developer.fidesmo.com/tutorials/android-totp
