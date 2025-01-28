# ToDo

- [x] Crypto
  - [x] Sync hash functions
  - [x] Async hash functions

- [ ] Tokens
  - [x] Sync signing
  - [x] Async signing
  - [ ] Verification
    - [x] Verify the algorithm used in the JWT header matches the expected one
    - [x] Check the signature using the public key (for RSA/ECDSA) or secret (for HMAC)
    - [ ] Decode the token and validate claims (issuer, audience, etc.)
    - [ ] Handle expired tokens (check exp claim)