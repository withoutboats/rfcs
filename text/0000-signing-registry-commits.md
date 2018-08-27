- Feature Name: verified_registry_commits
- Start Date: 2018-05-08
- RFC PR: (leave this empty)
- Rust Issue: (leave this empty)

# Summary
[summary]: #summary

Enable commits to crate registry indexes to be signed & verified, providing
stronger guarantees as to the authenticity of their content and (transitively)
guaranteeing the authenticity of the content of the packages in the registry.

# Motivation
[motivation]: #motivation

Crate registries like the crates.io registry are a way of distributing source
code which is ultimately built and executed on end user machines. It is vital
that users receive valid source files for the packages they download,
especially because a malicious package could be a major attack vector to harm
users of Rust, or users of those users' projects.

The index of a registry is a git repository downloaded by cargo over HTTPS or
SSH. This index contains information about each package, including a SHA-256
checksum of the content of that package. When cargo downloads a package from
the registry, its contents are verified against that checksum. This is intended
to guarantee that the content the user downloads is the same data this referred
to by the registry index.

However, a malicious or otherwise ill-behaved third party could conceivably
(such as with a MITM attack) intercept the download of the index and modify the
checksum of a package, allowing them later to modify the content of that
package when the user requests it. They could also, conceivably, modify the
index repository at its central storage, making similar malicious edits which
will be accepted by every user.

If the content of the registry index could be authenticated in a stronger way,
this would make it more difficult for an attacker to modify index data. Because
the registry is a git repository, and a git repository performs hashing of
structured content in a manner similar to a [merkle tree][merkle], signing a
commit verifies the content of all the data that commit contains (modulo the
security properties of the repository's hash function - a discussion of SHA-1 is
later in this RFC). Because a hash of each package contents is contained in the
index repository, the index as a whole can be thought of as a merkle tree, some
of the leaves of which are all of the packages in the registry.

Signing commits is an effective and cheap way to provide stronger authenticity
of package contents. It enables cheap key rotation, because a new signature on
the head of the index repository validates all of the content in the registry.
Because git already supports commit signing, it is a natural extension of our
existing practices, rather than a large scale re-engineering of the registry
system.

# Guide-level explanation
[guide-level-explanation]: #guide-level-explanation

For normal users, this change should be completely transparent. Whenever the
index is updated if the registry in question is a registry that ought to be
signed (a 'signed registry'), the signature of HEAD is verified against the
public keys which are permitted to sign commits to the index.

## Metadata Files

Public keys used to authenticate each signed registry are distributed in a
set of metadata files which are initially delivered via the crates.io index's
git repository and cached locally inside of a user's `.cargo` directory.

The metadata files are serialized as TOML and use a schema adapted from
[The Update Framework][tuf] (a.k.a. TUF), and largely follow the structure
described in section [3. The repository][tuf-spec-s3] in the
[The Update Framework Specification][tuf-spec].

However, where TUF defines its own signature formats and message enveloping
(e.g. CJSON), no canonicalization is applied to these TOML files and instead
authenticity is determined by signed git commits as authenticated via
OpenPGP-formatted signatures (for more information on differences from other
implementations of TUF, see the "TUF Implementation Notes" section below).

Authority for signing the index is separated into 2 different roles: root
and timestamp, which each have their own metadata file and signing keys:

[3. The repository]:

### Root Metadata (`/root.toml`)

The `root.toml` file is the root of TUF's authority hierarchy. It contains
one or more public keys which are used to sign changes to the metadata files
for all TUF roles, including itself (i.e. it can authorize rotation of itself).
The root key(s) is/are intended to be offline (the initial implementation will
have only one key, see "TUF Implementation Notes" below).

When specifying these roles, the trusted keys for each are listed, along with
the minimum number of those keys required to sign the role’s metadata allowing
for k-of-n threshold signatures. However, while supporting threshold signatures
with OpenPGP-formatted signatures used by git is possible, and even potentially
compatible with all existing git tooling including GitHub, initially we will
forgo them for simplicity's sake and require `1` for all thresholds.

The `root.toml` file consists of a toplevel object with the following members:

- `spec-version`: Version number of the TUF specification (`1` for now).
- `version`: Counter (starting at `1`) which is incremented when `root.toml`
  is updated.
- `consistent-shapshot`: Boolean indicating whether we support TUF's
  consistent snapshot feature. Set to `true` as git provides this property.
- `expires`: date (as described in [IETF RFC 3339][rfc3339]) which determines
  when metadata should be considered expired and no longer trusted by clients.
- `keys`: Object containing a mapping between a key ID (i.e. the string
  `openpgp:` followed by the 20-byte V4 key fingerprint as defined in section
  [12.2][RFC 4880#section-12.2] of [RFC 4880]. See "TUF Implementation
  Notes" section below for information) and an object containing
  information about the key:
  - `keytype`: String denoting the public key digital signature system used.
    Always `ed25519` for now.
  - `scheme`: String denoting the signature scheme. Always `openpgp` for now.
  - `keyval`: Object containing the `public` portion of the key, serialized as
     an ASCII armored OpenPGP public key (conforming to [RFC 4880]).
- `roles`: Object which maps a role name (one of `"root"`, `"snapshot"`,
  `"targets"`, `"timestamp"`, or `"mirrors"`) to the keys which are valid for
  that role. A role for each of `"root"` and `"timestamp"` MUST be specified.
  The roles of `"snapshot"`, `"targets"`, and `"mirror"` will not yet be used,
  however their presence in the `roles` section of `root.toml` SHOULD be
  allowed to allow them to be added in the future (see "TUF Implementation
  Notes" section below). Each role has the following members:
  - `keyids`: Array of IDs from the `keys` section which are authorized to
    sign for this particular role.
  - `threshold`: Number of signatures which are required for a signature to
    be considered authorized. Always `1` for now.

See also subsection "4.3. File formats: root.json" in section
[4. Document formats][tuf-spec-s4] in [The Update Framework Specification][tuf-spec].

#### Example `root.toml`

```toml
spec-version = 1
version = 1
consistent-snapshot = true
expires = "2030-01-01T00:00:00Z"

[keys]
"openpgp:1CCC030D310C5366B5EE51A1BF3303F7F69B6027" = { keytype = "ed25519", scheme = "openpgp" }
"openpgp:FF88733444562854EC62ABE84CB919A8625280AA" = { keytype = "ed25519", scheme = "openpgp" }

# root
[keys."openpgp:1CCC030D310C5366B5EE51A1BF3303F7F69B6027".keyval]
public = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEW4Qj1BYJKwYBBAHaRw8BAQdAGjRNDONuzczXxYGYDoSnghi07RoMT3765OUF
VfXHizi0HFJvb3QgU2lnbmVyIDxyb290QGNyYXRlcy5pbz6IlgQTFggAPhYhBDEa
LVA2bIo3P28sl2URgHbD//hwBQJbhCPUAhsDBQkVAugABQsJCAcCBhUKCQgLAgQW
AgMBAh4BAheAAAoJEGURgHbD//hwRQEBAPjxtct5mb7M6i+zulgV2Zof870Y7AtQ
RHeHncIqeOE2AP9A06yzHT1kAKhxaZfRsWmUve5RaazXI220gACTnWM/AQ==
=hSSC
-----END PGP PUBLIC KEY BLOCK-----
"""

# bors
[keys."openpgp:FF88733444562854EC62ABE84CB919A8625280AA".keyval]
public = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEW4QkXxYJKwYBBAHaRw8BAQdAn+OPbGdtmZgDK6jlOsgfQwTWw0V16F8gEGaa
Nu7HCvC0JUJvcnMgSW50ZWdyYXRpb24gQm90IDxib3JzQGNyYXRlcy5pbz6IlgQT
FggAPhYhBP+IczREVihU7GKr6Ey5GahiUoCqBQJbhCRfAhsDBQkB4TOABQsJCAcC
BhUKCQgLAgQWAgMBAh4BAheAAAoJEEy5GahiUoCq3EIA/jwnT7zT8NzeVT3ptaia
yyuCPRTr8FPyq1av4TVpmDkHAQCYMV0dMoE+OZ0AfHEtAMGEgnKy+P4tQDdJjbHP
HK4bDA==
=oJZE
-----END PGP PUBLIC KEY BLOCK-----
"""

[roles.root]
keyids = ["openpgp:1CCC030D310C5366B5EE51A1BF3303F7F69B6027"]
threshold = 1

[roles.timestamp]
keyids = [
    "openpgp:1CCC030D310C5366B5EE51A1BF3303F7F69B6027",
    "openpgp:FF88733444562854EC62ABE84CB919A8625280AA"
]
threshold = 1
```

### Timestamp Metadata (`/timestamp.toml`)

All commits to the repository are made by the timestamp role, which also signs
the commits (i.e. with an online key) and updates the `timestamp.toml` with a
new `version` and `expires` date. The expiration date is intended to be short,
thus allowing clients to quickly detect if they are being prevented from
obtaining the most recent metadata. Commits which are not signed by one of the
keys with the timestamp role MUST be rejected.

In the even there have not been any recent commits to the index and the
expiry is near, the timestamp role will create an otherwise empty commit
which only modifies the `timestamp.toml` file by incrementing the `version`
and `expires` fields.

The `timestamp.toml` file consists of a toplevel object with the following
members:

- `spec-version`: Version number of the TUF specification (`1` for now).
- `version`: Counter (starting at `1`) which is incremented when
  `timestamp.toml` is updated.
- `expires`: date (as described in [RFC 3339][rfc3339]) which determines
  when the index should be considered stale and no longer trusted by clients.

See also subsection "4.6. File formats: timestamp.json" in section
[4. Document formats][tuf-spec-s4] in [The Update Framework Specification][tuf-spec].
Note that the `"meta"` key from `timestamp.json` is omitted in this
implementation. See "TUF Implementation Notes" following this section.

#### Example `timestamp.toml`

```toml
spec-version = "1"
version = "123"
expires = "2019-01-01T00:00:00Z"
```

### TUF Implementation Notes

The implementation of TUF described above uses the concepts, metadata files,
schema, and structures from the upstream project, but diverges from the
upstream implementation in the following ways:

- **Git + OpenPGP signatures**: git's content hashing and OpenPGP signatures
  are used to authenticate all files. This provides what TUF describes as
  "consistent snapshots", i.e. all files are modified in atomic commits and
  clients always see a linear history. However, this has some overlap with
  TUF's signature formats and certain TUF roles (most notably the "snapshot"
  role, see below)
- **TOML**: used as an alternative serialization format vs TUF's  CJSON. This
  shouldn't be too problematic as TUF is already designed to support multiple
  serialization formats (including e.g. ASN.1 DER), and existing Rust
  implementations such as `rust-tuf` are already designed to support multiple
  serialization formats. Furthermore, Rust serialization libraries like serde
  make supporting multiple serialization formats simple.
- **OpenPGP V4 key fingerprints**: used as TUF key IDs, domain separated from
  TUF's native key ID format with the `openpgp:` prefix. This is done for
  two reasons: to avoid having two different key ID formats, and because we
  aren't using CJSON and therefore can't implement TUF's CJSON-based key
  fingerprinting algorithm. Instead, the key IDs are ordinary OpenPGP v4 key
  fingerprints which are computed using the SHA-1 hash function (see notes on
  SHA-1 in the "Security Considerations" section at the end of this document),
  and hash a message that includes an algorithm identifier and the public key
  (see items `d` and `e` in section section [12.2][rfc4880-s12.2] of
  [RFC 4880][rfc4480])
- **`timestamp` and `root` roles combined**: this RFC describes a setup where
  in practice all `root` keys would also be authorized as `timestamp` keys,
  which allows us to enforce the property that all commits are signed by the
  `timestamp` role. There is no security advantage to separating them (at least
  with a threshold of `1`), as a `root` key can rotate the `timestamp` key.
  Alternatively, the `root` role could modify `root.toml`, and a merge commit
  signed by the `timestamp` role could be used to add it to the index. This
  would still ensure that `HEAD` is always signed by the `timestamp` role
  without the need to conflate these two roles, at the cost of slightly more
  complicated verification logic.
- **No `meta` member of `timestamp.toml`**: The timestamp file as described
  in the TUF specification includes a `meta` field which provides a digest
  (e.g. SHA-256) over `snapshot.json`. However, we don't support a `snapshot`
  role (see below) as Git already provides consistent snapshots. Instead of
  that, a signer with the timestamp role signs a commit hash covering an
  atomic change to all of the files in the repository, including
  `timestamp.toml`, which provides what TUF describes as "consistent snapshot"
  functionality and therefore eliminates the need to lean on TUF metadata
  to accomplish the same thing, barring security concerns about the git
  and OpenPGP ecosystem (see "Security Considerations" section below).
- **No `snapshot` role**: this role is typically used to provide atomic
  updates of multiple metadata files. However, git provides this property for
  free, eliminating the need for snapshots. That said, omitting the snapshot
  role violates a MUST in the current TUF specification.
- **No `targets` role**: work on supporting the targets role is deferred
  until another Rust RFC is created describing the specific implementation.
  This means TUF can be implemented in a two-step process, first implementing
  commit signing for the crates.io index, and then layering support for
  end-to-end crate signatures created by cargo using developer-held keys as
  a secondary step. This dramatically reduces the scope of shipping an initial
  index signing implementation while still providing considerable value.
  See "Future Work" section below.

Otherwise, cargo should largely follow the workflow for a TUF client
application described in section [5. Detailed Workflows][tuf-spec-s5] in the
[The Update Framework Specification][tuf-spec].

## When is a registry a signed registry?

Registries are considered signed registries if either of these hold true:

1. Current `HEAD` is a signed commit (by any key).
2. A `/root.toml` file exists for that registry.

An attempt to update the `HEAD` of a signed registry to a commit that is not
signed by one of the timestamp role's keys is a hard failure that will
prevent cargo from resolving dependencies in that registry any longer. Until
the state is fixed, cargo will not generate lockfiles for crates that depend on
packages in that registry. This includes a commit which is not signed at all.

If the HEAD of a registry is signed but that registry has `/root.toml`, that
registry will be considered a signed registry, but in a broken state, because
HEAD is signed but there are no trusted signing keys. In general, this
definition of signed registry is supposed to "fail closed."

## Why PGP formatted keys?

This RFC specifies that keys and signatures are exchanged using PGP format,
even though it also adds that cargo will not ship a full PGP implementation to
verify signatures. The PGP format is a rather complex binary format which
supports many options that are not relevant for our use case: as a result,
we've specified that we only support a subset of the PGP format. One could
fairly ask why we use PGP at all instead of a more straightforward solution.

The primary reason to use the PGP format is to integrate with existing git &
gpg tooling. The subset of PGP we support is compatible with keys generated by
gpg2 and with signatures on commits made with `git commit -S`. This allows
users to manually produce and verify signatures as necessary either for
administrative purposes or to check the correctness of cargo's behavior.
Additionally, GitHub has a mechanism to host GPG keys associated with a GitHub
account, which would not be possible for a custom key format.

## Advisory for people running registries

cargo will only validate the signature of the `HEAD` commit, no intermediate
commits. All committers to the registry **MUST** verify the signature of
parents to their commits, or the security properties of this system will be
violated.

Registries are free to make their own policies regarding the distribution of
keys and when to perform rotations, but if a registry operator commits
without verifying the signature of that commit's parents, they have
nullified the benefits of running a signed registry over an unsigned
registry.

# Reference-level explanation
[reference-level-explanation]: #reference-level-explanation

## Signature schemes & data formats supported by cargo

Though keys are stored in the OpenPGP format, cargo will not actually verify
signatures using a complete OpenPGP implementation such as gpg, which would be
a significant new C dependency to ship to all users. Instead, cargo will use
pure Rust implementations of established signature schemes, as well as a pure
Rust parser for a subset of the OpenPGP format.

All signatures are valid OpenPGP signatures, which means they are signatures of
hashes of the data being signed as well as metadata in accordance with the
OpenPGP spec ([IETF RFC 4880][rfc4880]).

### OpenPGP subset

All signatures and public keys will be distributed in a subset of the data
format described in RFC 4880 which is consistent with the behavior of recent
versions of gpg2 (allowing the manual creation of signatures and keys as
necessary).

These are the requirements for a signature or public key to be supported by
cargo:

- It uses what RFC 4880 calls the "old format packet header" for all packets
- All packets have a two octet length (so the packet header is 3 octets long).
- Signatures and public keys are both version 4 of their format.
- It uses one of cargo's supported signature and hash algorithms.
- The first hashed subpacket of any signature is the public key fingerprint
  with subpacket type 33 (note this is the 20 byte fingerprint, not the 8 byte
  key ID).

This conforms to the default behavior of gpg2 and is what is accepted and
generated by [a Rust implementation of a subset of OpenPGP written by the
RFC author][pbp].

### Signature and hash algorithms

Our initial implementation will support only one signature algorithm and one
hash algorithm. This may be extended in time. The signature algorithm is EdDSA
with the twisted Edwards form of Curve25519 (Ed25519) and the hash algorithm
is SHA-256.

## Signature distribution format

Signatures are distributed in the same manner that git distributes commit
signatures - as an ASCII armored OpenPGP signature included in the commit
object which authenticates the commit's message, contents and other headers.
This way, users can verify index commits using their own version of git, and
administrations making manual edits to the registry can use git to generate
the signatures.

## Key rotation

Key rotation is performed by creating a commit to the index which modifies
`root.toml`, and then creating a signed "key rotation tag" using one of the
keys with access to the root role.

A key rotation tag should point to the HEAD commit of the registry index at the
time it is made. The commit it points modifies `root.toml` and MUST be signed
using a key which is authorized to sign for the root role both before and after
`root.toml` is modified. Any commits which modify `root.toml` which do not meet
these criteria MUST be rejected by clients. 

The name of a key rotation tag must be `root-rotation-v$SPECVERSION-$N` where
$SPECVERSION corresponds to the `spec-version` number in the `root.toml` file,
and $N cooresponds to the `version` number.

When cargo updates the index, it will iterate through the new tags matching
this format that have been added to the repository in their order in the commit
history. cargo will verify that the tag is signed by a key which is in the
set of `root` keys (for both the local copy of `root.toml` as well as the
one included in the git commit) and update the local copy of the `root.toml`
file kept in the `.cargo` directory.

## crates.io initial policy

The initial policy for role assignments for crates.io keys is as follows:

- **Rust core team**: All `root` keys will be held offline by members of the
  Rust core team who have volunteered to be key custodians. The initial
  signing threshold will be `1`, i.e. any of these individuals can update
  `root.toml` singlehandedly. Ideally they will use hardware key storage.
  Additionally, in order to enforce the constraint that *all* commits must be
  signed by the timestamp role, these same keys will also be authorized to
  sign as the timestamp role (see "TUF Implementation Notes" for alternatives).
  git commits which update `root.toml` MUST also update `timestamp.toml`,
  with a monotonic increment-by-one version number.
- **bors**: A single key, belonging to the bors account, will be accessible
  online from the the crates.io service. This key will only be authorized for
  the `timestamp` role. The bors key will be used to sign every commit to the
  crates.io index aside from ones signed by one of the root keys (which will
  also have the timestamp )

Keys, especially the online bors key, may be rotated at irregular intervals,
not necessarily because of a known compromise. An explanation of the rotation
will always be published at rust-lang.org. We do not commit to any particular
rotation schedule.

## Security considerations

### Trust on first use

When a user first downloads a registry index, or transitions an index from
unsigned to signed, they have no pre-existing trusted keys for that registry.
For this reason, the first access of a signed registry is a leap of faith in
which the user also obtains the keys to trust for future updates. A successful
attack at that point would leave the user will with an invalid index.

We can harden crates.io against attacks at this point by distributing the
current trusted keys with the rustup distribution, allowing any security
mechanisms we put in place for the distribution of Rust and cargo binaries to
also secure this operation.

### An attacker with no keys

An attacker with no keys cannot sign commits or rotation tags. Because of this,
an attacker with no keys would not be able to modify the registry index, even
if they were able to defeat the existing security measures like our use of
HTTPS or SSH to transmit the index data over the network.

However, such an attacker could still prevent the user from receiving updates
to the index by - for example - MITMing their connection to the git server to
report that there is no update. Such an attack could keep users from receiving
essential security updates to their dependencies. Hardening cargo against this
sort of attack is left as future work.

### An attacker that can forge signatures for the `timestamp` role

An attacker who has compromised a key with `timestamp` role access could
make commits to the index, modifying the data. This would essentially revert
the system to its security properties before this RFC.

However, if a key compromise of this sort is discovered, an automated key
rotation could remove the compromised key from the set, restoring the security
properties of the system.

### An attacker that can forge signatures for the `root` role

An attacker who has compromised a key with `root` role access could
rotate the key set, adding and removing keys at will. This would allow them to
take control of the index, preventing legitimate updates (such as key
rotations) from reaching users. If a `root` key were compromised, it would
likely be very disruptive to all users.

For that reason, crates.io will adopt policy that `root` keys are stored in an
offline medium, with due security precautions. As a future hardening, we could
also implement threshold signatures, requiring signatures from multiple `root`
keys to perform a key rotation, reducing the impact of compromising a single
key with this privilege.

### SHA-1

The security of this system hinges on the security of SHA-1, which is used for
both computing the digests of git objects/commits as well as OpenPGP V4 key
fingerprints. SHA-1 is known to be cryptographically broken in that collision
attacks have been performed in practice. A successful collision attack against
a crate index would nullify the security benefits of this RFC: an attacker would
be able to swap out one commit for another which would both appear to be signed.

However, there are a few mitigating factors which make this RFC worthwhile to
pursue despite these problems:

1. The SHAttered collision attack depends on the ability to control data in
both colliding objects in order to create a collision (that is, they cannot
create a collision with an arbitrary hash). Hypothetically, an attacker could
upload a crate to the registry with index metadata that they can use to create
a collision; however, this increases the difficulty significantly in comparison
to the SHAttered case.
2. Even the SHAttered case was prohibitively expensive. Breaking into one of
our administrators' homes to copy their signing key is probably cheaper.
3. Our current git host, GitHub, checks for the signs of this sort of collision
attack and would not accept an object containing a collision.

That said, we take the weakness of SHA-1 seriously, and will commit to
switching to a stronger hash function as soon as it is possible for us to do
so. In order to do that, git needs to be updated to support a new hash
function, and that upgrade needs to be supported by both GitHub (which hosts
our index) and libgit2 (which cargo uses for git operations). Work is underway
to upgrade git to a known-secure digest algorithm, which the crates.io index
can be updated to once it becomes available.

## Future Work

### Threshold Signatures

One of [The Update Framework][tuf]'s key features is threshold signatures:
supporting a k-of-n scheme where e.g. at least two keyholders must both sign
in order for something to be considered authorized. This reduces the risk of
having more authorized signers by limiting the exposure of a single
compromised key.

The OpenPGP signature format allows for 1-or-more signature packets within
a single signature message. The [parse_gpg_output()] function in git's
`gpg-interface.c`, when given message containing multiple signature packets,
only extracts the last one and attempts to verify it, and ignores the others.
GitHub appears to follow suit (possibly using the same code).

This means threshold signatures could be implemented by encoding the signatures
as a single ASCII armored signature message containing multiple signature
packets in a backwards compatible way wwithout (based on initial research)
breaking any existing tooling and also still makes sense in a single-signature
context.

### Targets Role: End-to-End Crate Signing

[The Update Framework][tuf] can be leveraged for much more than just signing
crate registry indexes. It is designed to provide a comprehensive solution for
package security, and as such, this work could be extended to provide a full
end-to-end crate signing, where crates are signed by cargo using keys held
by individual developers.

This means the work described herein could be extended into such a solution
by adding the `targets.json` file, described in subsection
"4.5. File formats: targets.json and delegated target roles" in section
[4. Document formats][tuf-spec-s4] in [The Update Framework Specification][tuf-spec].
Specifically TUF's "Delegated Targets" feature could be used to delegate
signing authority for some subset of the crates.io index to keys held by
end developers, i.e. owners of a crate could be allowed to sign changes to
the index related to that crate.

There are a lot of specific implementation details to consider in such a scheme:

- Should git commits also be used for this purpose? e.g. a developer could sign
  a commit containing the index changes which are then verified by bors and
  merged as part of a signed merge commit. A similar process could be used for
  better separating the timestamp and root roles.
- Which signers would be authorized to sign `targets.toml`? How would it be
  implemented in practice? The simplest option is to also allow bors to sign
  for the targets role in addition to the timestamp role, but this means a
  compromise of bors represents a compromise of all delegated targets. This
  could potentially be resolved by giving the targets role a "delegate once"
  authority, e.g. the key for the targets role could support purely additive
  changes (e.g. bors could fetch a user's public key from GitHub and add it
  to `targets.toml` as a target delegation), whereas modifications to the
  authorized keys for a crate/delegated target role would require a signed
  commit which follows the same policy as the role itself. In the event users
  lock themselves out, it would be possible for the root role to manually
  override the key set for that crate/target.
- Should the targets role be a separate service? Since the targets role is so
  security critical, it might make sense to split it out of the regular
  crates.io service into its own separate service, which crates.io would only
  call out to in the event that `targets.toml` needs to be updated (e.g. a
  crate is enrolled as a delegated target for the first time, `cargo owner`
  is used to add/remove authorized users/crate signers, or a user has updated
  a key on GitHub and it needs to be reflected in `targets.toml`). This
  service could effectively act as a notary, with keys managed through GitHub's
  GPG key management feature. It could go down with a low impact to crates.io
  overall, and it could potentially be run by multiple parties using k-of-n
  signatures, e.g. the Rust Infrastructure Team, the Google Fuchsia Team,
  and Galois (or any other Rust-using companies/organizations with the
  requisite infrastructure security experience) could operate the service
  with 2-of-3 signatures required.

#### Example `targets.toml`

The following is an example of what a prospective `targets.toml` containing
delegated crate targets might look like:

```toml
spec_version = 1
version = 1
expires = "2030-01-01T00:00:00Z"

[delegations.keys]
"openpgp:CF88733444562854EC62ABE84CB919A8625280AZ" = { keytype = "ed25519", scheme = "openpgp" }
"openpgp:DCCC030D310C5366B5EE51A1BF3303F7F69B6022" = { keytype = "ed25519", scheme = "openpgp" }

[delegations.keys."openpgp:CF88733444562854EC62ABE84CB919A8625280AZ".keyval]
public = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
[...]
-----END PGP PUBLIC KEY BLOCK-----
"""

[delegations.keys."openpgp:DCCC030D310C5366B5EE51A1BF3303F7F69B6022".keyval]
public = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
[...]
-----END PGP PUBLIC KEY BLOCK-----
"""

[[roles]]
name = "lazy_static"
keyids = ["openpgp:CF88733444562854EC62ABE84CB919A8625280AZ"]
paths = ["/la/zy/lazy_static"]
threshold = 1

[[roles]]
name = "serde"
keyids = ["openpgp:DCCC030D310C5366B5EE51A1BF3303F7F69B6022"]
paths = ["/se/rd/serde"]
threshold = 1

[targets."config.json"]
hashes = { sha256 = "5b3e89dcc6c9711a7210f145c6530f234cbc6bbda6dd630c2244cffc58ea6826" }
length = 77
```

# Drawbacks
[drawbacks]: #drawbacks

The primary drawback of this is that it increases the operational complexity of
managing crates.io, and the complexity of the cargo codebase. The Rust
infrastructure and dev-tools teams would be taking on the burden of maintaining
this system & provisioning and protecting secret keys. The additional security
benefits of this RFC will depend on their key management practices.

# Unresolved questions
[unresolved]: #unresolved-questions

No major unresolved questions as of this time.


[merkle]: https://en.wikipedia.org/wiki/Merkle_tree
[rfc3339]: https://tools.ietf.org/html/rfc3339
[rfc4880]: https://tools.ietf.org/html/rfc4880
[rfc4480-s12.2]: https://tools.ietf.org/html/rfc4880#section-12.2
[pbp]: https://github.com/withoutboats/pbp
[tuf]: https://theupdateframework.github.io/
[tuf-spec]: https://github.com/theupdateframework/specification/blob/master/tuf-spec.md
[tuf-spec-s3]: https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#3-the-repository
[tuf-spec-s4]: https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#4-document-formats
[tuf-spec-s5]: https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#5-detailed-workflows
[parse_gpg_output()]: https://github.com/git/git/blob/4d34122eef19c39415d38b4963572770f96a9317/gpg-interface.c#L92
