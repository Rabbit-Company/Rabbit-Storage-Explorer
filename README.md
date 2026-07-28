# Rabbit Storage Explorer

A fast, native storage explorer for **S3-compatible object stores, SFTP (SSH),
NFS and SMB servers**, built with **Rust + GTK4 + libadwaita**. Designed for
bulk drag-and-drop uploads (thousands of small files) with optional
**end-to-end encryption**.

- Four backends behind one UI: **S3-compatible storage**, **SFTP over SSH**,
  **NFSv3** and **SMB 2/3** (all pure Rust, no system libraries) - browse,
  upload, download, delete
- Drag & drop files _and folders_ anywhere in the window to upload
- Connection manager: save multiple connections, connect with one click
  (E2EE connections just ask for the password), edit or delete saved entries
- Parallel transfer engine (defaults: 12 concurrent uploads, 6 downloads) with
  retries and cancellation
- Survives network changes: if the connection drops mid-transfer (Wi-Fi switch,
  brief outage), the app reconnects automatically and retries the affected files
- Optional E2EE: file **contents and names** are encrypted on your machine before
  upload - the server only ever sees ciphertext
- All I/O, crypto and network work runs on a background tokio runtime; the GTK
  main thread only paints, so the UI never freezes
- Secrets stored in the OS keychain, not in config files

## Building

Requires **Rust 1.88+**, **GTK 4.10+** and **libadwaita 1.5+** development files.

```bash
# Ubuntu 24.04+ / Debian 13+
sudo apt install build-essential pkg-config libgtk-4-dev libadwaita-1-dev

# Fedora 40+
sudo dnf install gtk4-devel libadwaita-devel

# Arch
sudo pacman -S gtk4 libadwaita base-devel
```

```bash
cargo build --release
./target/release/rabbit-storage-explorer
```

## Connecting

### S3-compatible storage

1. Create API credentials with read/write access to your bucket in your
   provider's dashboard.
2. In the app choose type **S3-compatible storage** and fill in:
   - **Endpoint URL:** your provider's S3 endpoint, e.g. `https://s3.example.com`
   - **Bucket**, **Access key ID**, **Secret access key**

The client uses path-style addressing and the `auto` region, which works with
the vast majority of S3-compatible providers.

### SFTP (SSH)

Choose type **SFTP (SSH)** and fill in host, port (default 22) and username.
Authentication is either:

- **Password** - leave the key path empty and enter the password in the secret
  field, or
- **Private key** - set the key file path (`~/.ssh/id_ed25519` style paths
  work); the secret field then holds the key's passphrase (leave empty for
  unencrypted keys).

An optional **remote directory** sets the starting folder (defaults to the
user's home directory). Host keys are verified **trust-on-first-use**: the
first connection records the server's fingerprint in `known_hosts.json` in the
app config directory, and later connections refuse to proceed on a mismatch -
checked before any credentials are sent. If a server's key legitimately
changed, remove its entry from that file.

### NFS

Choose type **NFS** and fill in the host and the **export path** (as listed by
`showmount -e <host>`, e.g. `/srv/nfs/share`). The client speaks NFSv3 with
AUTH_UNIX directly over TCP - no kernel mount and no root privileges needed.
Access control on such exports is uid/gid based: set the **UID/GID** fields to
an identity the export accepts (`all_squash`/`anonuid` exports accept anything).
Leave the port at 0 to discover it via the server's portmapper.

Note that AUTH_UNIX is not cryptographic authentication - anyone who can reach
the server can claim any uid. Use NFS on trusted networks, or combine it with
this app's end-to-end encryption so the server only ever stores ciphertext.

### SMB / Windows shares

Choose type **SMB / Windows share** and fill in host, share name, username and
password (domain/workgroup optional, port 445 by default). The client is the
pure Rust `smb2` crate - SMB 2/3 with signing, encryption, compression and
compound/pipelined I/O - and talks to Windows servers, Samba, and NAS devices
without libsmbclient being installed. An optional directory limits browsing to
a subtree of the share.

### Saved connections

Saved connections appear on the start screen; click one to connect. Encrypted
connections prompt only for the encryption password (the secret comes from the
keychain). If the keychain has no entry for a profile - for example on a new
machine - the app falls back to the edit form so you can re-enter the secret.

## E2EE format (v1)

- **KDF:** Argon2id (OWASP defaults) over your password + a random 16-byte salt
  -> 32-byte master key -> HKDF-SHA256 -> separate content and filename keys.
- **Content:** XChaCha20-Poly1305, 1 MiB chunks. Header `RSE1 || file_prefix(20)`
  (24 bytes); chunk nonce = `file_prefix || counter`, with the final chunk's
  counter high bit set so truncation is detected. The 160-bit random per-file
  prefix makes nonce reuse across files astronomically unlikely even at very
  large file counts. Works streaming - large files are encrypted and uploaded
  without ever being fully in RAM.
- **Filenames:** each path segment is encrypted with AES-256-SIV (deterministic)
  and then stored on the backend under `SHA-256` of that ciphertext, as a 64-char
  uppercase-hex name. Hashing keeps on-disk names a fixed length - so arbitrarily
  long names work even though most filesystems cap a segment at 255 chars - while
  staying deterministic, so the app can compute exactly where a file lives without
  reading anything. The real name and plaintext size live in the directory's
  encrypted manifest (below). Trade-off: because the mapping is deterministic, an
  observer can still see that two objects share a name or folder, but not what the
  name is, and no longer learns anything from name lengths.
- **Directory manifests (`.rse`):** each directory holds one `.rse` object - a
  JSON map from each on-disk hash to its real name and unencrypted size, plus
  optional cached recursive folder sizes - encrypted as a whole with the content
  key (so the server sees only ciphertext for metadata too). Listing a directory
  is therefore a single manifest read, and file sizes shown are the true plaintext
  sizes. Manifests are buffered in memory and written back on a short interval
  (default 10 s, in Settings) and at the end of each batch, to keep request counts
  and costs low; **exactly one instance should manage an encrypted bucket at a
  time.** If the app is interrupted mid-upload, freshly written objects can briefly
  outrun their manifest entry; such items are shown as `[unrecovered]` in the
  listing (never hidden) and are restored by re-uploading, which lands on the same
  deterministic name.
- The first E2EE connection initializes a small `.rse-vault` file (random salt +
  an encrypted canary used to verify your password on later connects). Its
  location is the storage unit's root: the bucket root for S3, the export root
  for NFS, the configured directory for SMB. For SFTP it is anchored to the
  _account_, not the browsed directory: it lives in the SSH user's home
  (`/home/ziga/.rse-vault`), so changing the connection's remote directory
  still opens the same vault and previously encrypted data stays readable.
  Accounts without a home directory share a global vault at
  `/var/lib/rabbit-storage-explorer/.rse-vault` (world-readable; an admin may
  need to `mkdir -m 1777 /var/lib/rabbit-storage-explorer` first). The
  password itself is never stored anywhere.

**Warnings that come with real E2EE:** if you lose the password, the data is
unrecoverable - there is no reset. Mixing encrypted and unencrypted files in one
location works but is best avoided.

## Defaults (changeable in Settings ⚙)

| Setting                 | Default | Why                                                                         |
| ----------------------- | ------- | --------------------------------------------------------------------------- |
| Parallel uploads        | 12      | Thousands of small files are latency-bound; parallelism wins                |
| Parallel downloads      | 6       | Balanced against local disk write pressure                                  |
| Multipart threshold     | 64 MiB  | Small objects are cheaper as single PUTs                                    |
| Part size               | 16 MiB  | Fewer requests per large file; the S3 minimum is 5 MiB                      |
| Retries                 | 500000  | Retries per object before it is reported as failed                          |
| Reconnect interval      | 3       | Delay between reconnect/retry attempts after the connection drops (seconds) |
| Manifest flush interval | 10      | How often encrypted directory metadata is saved back (seconds)              |
