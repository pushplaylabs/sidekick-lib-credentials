# Library Credentials

## Quickstart

```sh
npm i -S git+ssh://git@github.com/pushplaylabs/sidekick-lib-credentials#master
```

And start use in your code:

```js
import { init } from 'sidekick-lib-credentials'

const {
  prepareUserCredentials,
  initRecoveryKey,
  createKeySet,
  createEncryptedKeySet,
  createEncryptedCredential,
  createCredential,
} = init()
```

## **S**tanford **J**avascript **C**rypto **L**ibrary

### Build:

```sh
git clone https://github.com/bitwiseshiftleft/sjcl.git
cd sjcl
```

Need to make some diff to include **HKDF**:

```patch
diff --git a/configure b/configure
index abc6dd8..bef64a5 100755
--- a/configure
+++ b/configure
@@ -4,7 +4,7 @@ use strict;

 my ($arg, $i, $j, $targ);

-my @targets = qw/sjcl aes bitArray codecString codecHex codecBase32 codecBase64 codecBytes codecZ85 sha256 sha512 sha1 ccm ctr cbc ocb2 ocb2progressive gcm hmac pbkdf2 scrypt random convenience bn ecc srp ccmArrayBuffer codecArrayBuffer ripemd160/;
+my @targets = qw/sjcl aes bitArray codecString codecHex codecBase32 codecBase64 codecBytes codecZ85 sha256 sha512 sha1 ccm ctr cbc ocb2 ocb2progressive gcm hmac hkdf pbkdf2 scrypt random convenience bn ecc srp ccmArrayBuffer codecArrayBuffer ripemd160/;
 my %deps = ('aes'=>'sjcl',
             'bitArray'=>'sjcl',
             'codecString'=>'bitArray',
@@ -23,6 +23,7 @@ my %deps = ('aes'=>'sjcl',
             'ocb2progressive'=>'ocb2',
             'gcm'=>'bitArray,aes',
             'hmac'=>'sha256',
+            'hkdf'=>'hmac',
             'pbkdf2'=>'hmac',
             'scrypt'=>'pbkdf2,codecBytes',
             'srp'=>'sha1,bn,bitArray',
@@ -41,7 +42,7 @@ my %enabled = ();
 $enabled{$_} = 0 foreach (@targets);

 # by default, all but codecBytes, codecZ85, srp, bn
-$enabled{$_} = 1 foreach (qw/aes bitArray codecString codecHex codecBase32 codecBase64 sha256 ccm ocb2 gcm hmac pbkdf2 random convenience/);
+$enabled{$_} = 1 foreach (qw/aes bitArray codecString codecHex codecBase32 codecBase64 sha256 ccm ocb2 gcm hmac hkdf pbkdf2 random convenience/);
```

```sh
./configure --with-codecBytes
make sjcl.js
```
