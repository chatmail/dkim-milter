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

INSERT INTO signing_keys VALUES
  ('key1', '-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAKCYaurTirsbpkHt/ey/U4ojE2KtJE9i6MjO9a23QPh
-----END PRIVATE KEY-----'),
  ('key2', '-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMA2F64ztjcTa50Z
/tZAcgwuqAxSEYhYZriq1q7wZTaAT/dy/O7oGC1qzcxo30FNuklBD2UOv3lHJ/PZ
l18SyuLGd9FndwHGBdvH+0JYGNFWOKNvNdhQZNsPR0SFE3V/vDrOtoE2tbFCJopT
hskBB+Et1epjCLNlAAtu4tDYqYBVAgMBAAECgYAks6994f3vMlQgIXCZtKCSVu5b
u+gBIvAqXuSzbs/EwmeCloBZlhPXyEcXuwa2T4M8raGk6FYDcGTemTPgQZRfuEcp
Xm/e0xl+d2KzZsjIRMG8kQgCnmDwP15dYhDVjekPh+H75k9uoI9VlJ1NdE32Ea6l
mkBUY9PXJXHDQflogQJBAOVS0LMCMESPddhORBXH6s1cAyLkzIPOmD/lViGFWPzy
YZlWuNpVawDdIpdzg2CI/QhNTUnD+TKFz5MHfJOgfhECQQDWkhZQ2IqU4+S2FewF
mHqSUBmNUUIAo4uXEnXjSORxeB0GX6oUDbDBOeVXnOfmjX1rHTALRvbpHRfedOgZ
FGoFAkEAnKZVqfJ0xmC5P2k3WSmXW3DfM5bXnbIijoM6sutEPoXT5cs3uu1eitiE
KLDfrbHmJyWnBhy4vapqgSU8FBwuAQJBAMpPM3tGsGNx/FMymDcubWNG4tC7rN+t
VBA896o1MC9McRFxYYtG3UFStUrGRmC7R2WXP5Vic6uYIsk8sRn0hYECQQDLS+ES
Bub386hfXcbnrvm6I8QFGfstpLPuU9QCGxFEWPLynpjTz+ik9mt7PMFVj33qMmgk
SxY0BJN2TMkg+O9j
-----END PRIVATE KEY-----');

INSERT INTO signing_senders VALUES
  ('example.com', 'example.com', 'sel1', NULL, 'key1'),
  ('example.com', 'example.com', 'sel2', NULL, 'key2');

INSERT INTO connection_overrides VALUES
  ('1.2.3.0/24', 'expiration = never
limit_body_length = no
');

INSERT INTO recipient_overrides VALUES
  ('.example.com', 'expiration = never
limit_body_length = no
');
