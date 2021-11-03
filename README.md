# agekms

This repo contains implementations supporting use of
[age](https://filippo.io/age) as a library with an RSA `ASYMMETRIC_DECRYPT`
key in Google Cloud KMS.

## Structure

The `rsaoaep` module implements a recipient suitable for use with the identity
implemented in `gcpkms`.

The project is split into separate modules to avoid introducing
Google Cloud SDK version constraints on encrypt-only users.

## Project Status

This project is open-source mostly as an example.

This implementation does not have tests (yet).

You should not consider anything about this library to be stable.

### Contributing

This is unlikely to receive much maintenance or attention, so if you want
to use this code, forking it is probably the way to go.

If you want to send a PR, please include a Signed-Off-By in all commits to
make the certifications in the [DCO](DCO.txt) explicit.
