# ToDo

- [x] Crypto
  - [x] Sync hash functions
  - [x] Async hash functions

- [x] Tokens
  - [x] Sync signing
  - [x] Async signing
  - [x] Verification
    - [x] Verify the algorithm used in the JWT header matches the expected one
    - [x] Check the signature using the public key (for RSA/ECDSA) or secret (for HMAC)
    - [x] Decode the token and validate claims (issuer, audience, etc.)
    - [x] Handle expired tokens (check exp claim)