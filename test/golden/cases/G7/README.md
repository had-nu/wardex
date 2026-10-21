# G7 fixture keys

`admin` and `admin.pub` are an Ed25519 keypair generated for these tests. They
are test data, not secrets, and protect nothing outside this directory. The
trust store in each case is signed by that key and is a fixed fixture: the
cases exercise verification and sealing, never key generation.

To regenerate the fixtures, run `wardex keygen --out admin`, then
`wardex trust init --actor admin@example.com --name "Golden Admin" --keyring
admin --out wardex-trust.yaml` and update the timestamps in the committed
files.
