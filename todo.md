# ToDo

- [ ] Crypto
  - [x] Sync hash functions
  - [ ] Async hash functions

- [ ] Tokens
  - [x] Sync signing
  - [ ] Async signing
  - [ ] Verification
    - [ ] Verify the algorithm used in the JWT header matches the expected one
    - [ ] Check the signature using the public key (for RSA/ECDSA) or secret (for HMAC)
    - [ ] Decode the token and validate claims (issuer, audience, etc.)
    - [ ] Handle expired tokens (check exp claim)