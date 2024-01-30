--
-- Schema for SQLite (draft)
--

-- Table signing_keys
--
-- key_id is an arbitrary, unique identifier for the key.
-- key_pem is the signing key in PKCS#8 PEM form.
CREATE TABLE signing_keys (
  key_id text PRIMARY KEY,
  key_pem text NOT NULL
);

-- Table signing_senders
--
-- sender is a sender expression.
-- domain is a domain name or identity expression.
-- selector is a selector.
-- signature_overrides contains configuration parameters for signing.
-- signing_key references a key in signing_keys by its key_id column.
CREATE TABLE signing_senders (
  sender text NOT NULL,
  domain text NOT NULL,
  selector text NOT NULL,
  signature_overrides text,
  signing_key text REFERENCES signing_keys
);

-- Table connection_overrides
--
-- network is a network address.
-- config contains configuration parameters for signing and verification.
CREATE TABLE connection_overrides (
  network text NOT NULL,
  config text NOT NULL
);

-- Table recipient_overrides
--
-- recipient is a recipient expression.
-- config contains configuration parameters for signing and verification.
CREATE TABLE recipient_overrides (
  recipient text NOT NULL,
  config text NOT NULL
);


--
-- Example data
--

INSERT INTO signing_keys VALUES ('key1', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAKCYaurTirsbpkHt/ey/U4ojE2KtJE9i6MjO9a23QPh
-----END PRIVATE KEY-----');

INSERT INTO signing_senders VALUES ('example.com', 'example.com', 'default', NULL, 'key1');

INSERT INTO connection_overrides VALUES ('1.2.3.0/24', 'expiration = never
limit_body_length = no
');

INSERT INTO recipient_overrides VALUES ('.example.com', 'expiration = never
limit_body_length = no
');
