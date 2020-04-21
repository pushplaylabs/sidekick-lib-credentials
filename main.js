import { nanoid } from 'nanoid'
import sjcl from 'sjcl'

class Key {
  constructor({ key, kid, jwk }) {
    if (key) {
      this.crypto = key
      this.id = kid

      return KeyExport(key, kid).then(result => {
        this.jwk = result

        return this
      })
    } else {
      this.jwk = jwk
      this.id = jwk.kid
      return JwkImport(jwk).then(result => {
        this.crypto = result

        return this
      })
    }
  }
}

// publicKey: jwk format
// data: raw data to encrypt
// returns
// { key, encrypted }
class Credential {
  constructor({ publicKey, data }) {
    this.data = data
    return new Key({ jwk: publicKey })
      .then(publicKey => new CredentialKey({ publicKey }))
      .then(key => (this.key = key))
      .then(this.encrypt)
      .then(() => this)
  }

  encrypt = () => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12))

    return Encrypt(iv, this.key.crypto(), textEncode(JSON.stringify(this.data)))
      .then(result => bytesToBase64(new Uint8Array(result)))
      .then(
        data =>
          (this.encrypted = {
            kid: this.key.id(),
            enc: 'A256GCM',
            cty: 'b5+jwk+json',
            iv: bytesToBase64(iv),
            data,
          }),
      )
  }
}

class CredentialKey {
  constructor({ publicKey }) {
    return KeyGenerate()
      .then(key => new Key({ key, kid: nanoid() }))
      .then(key => (this.key = key))
      .then(() => this.encrypt(publicKey))
      .then(() => this)
  }

  encrypt(publicKey) {
    const encodedKey = textEncode(JSON.stringify(this.key.jwk))

    return RsaEncrypt(publicKey.crypto, encodedKey)
      .then(result => bytesToBase64(new Uint8Array(result)))
      .then(data => {
        this.encrypted = {
          kid: publicKey.id,
          enc: 'RSA-OAEP',
          cty: 'b5+jwk+json',
          data,
        }
      })
  }

  crypto() {
    return this.key.crypto
  }

  id() {
    return this.key.id
  }
}

class EncryptedCredential {
  constructor({ encryptedData, encryptedKeyData, privateKey, id }) {
    this.encryptedData = encryptedData
    this.id = id
    return new EncryptedCredentialKey({ encryptedData: encryptedKeyData, privateKey })
      .then(key => (this.key = key))
      .then(this.encrypt)
      .then(data => (this.data = data))
      .then(() => this)
  }

  encrypt = () => {
    return Decrypt(this.encryptedData.iv, this.key.crypto(), this.encryptedData.data)
  }
}

class EncryptedCredentialKey {
  constructor({ encryptedData, privateKey }) {
    this.encryptedData = encryptedData
    return this.decrypt(privateKey)
      .then(jwk => new Key({ jwk: JSON.parse(jwk) }))
      .then(key => (this.key = key))
      .then(() => this)
  }

  decrypt(privateKey) {
    return RsaDecrypt(privateKey.crypto, this.encryptedData.data)
  }

  crypto() {
    return this.key.crypto
  }
}

const RecoveryKey = user => {
  var get = () => {
    return window.localStorage.getItem(`USER_${user.id}`)
  }

  var reset = () => {
    return window.localStorage.removeItem(`USER_${user.id}`)
  }

  var set = value => {
    return window.localStorage.setItem(`USER_${user.id}`, value)
  }

  var id = () => {
    return get().split('-')[0]
  }

  var value = () => {
    return get().split('-').slice(1).join('')
  }

  return { get, set, id, value, reset }
}

const EncryptedKeySet = (user, rawPublicKey, publicKeyId, encryptedPrivateKey, salt) => {
  var salt = salt
  var publicKeyId = publicKeyId
  var encPrivateKey = encryptedPrivateKey
  var recoveryKeyString = RecoveryKey(user).get()
  var _recoveryKey = recoveryKeyString.split('-').slice(1).join('')
  var _recoveryKeyId = recoveryKeyString.split('-')[0]

  var _publicKey, _privateKey, _mainKey

  var mainKeyGenerator = MainKeyGenerator({
    recoveryKey: _recoveryKey,
    recoveryKeyId: _recoveryKeyId,
    user,
    salt,
  })

  var generateMainKey = () => {
    return mainKeyGenerator.generate().then(key => new Key({ key, kid: 'main' }))
  }

  var initPublicKey = () => {
    return new Key({ jwk: rawPublicKey })
  }

  var decryptPrivateKey = () => {
    return Decrypt(encryptedPrivateKey.iv, _mainKey.crypto, encryptedPrivateKey.data).then(
      result => new Key({ jwk: JSON.parse(result) }),
    )
  }

  var decryptAll = () => {
    return generateMainKey()
      .then(key => (_mainKey = key))
      .then(decryptPrivateKey)
      .then(key => (_privateKey = key))
      .then(initPublicKey)
      .then(key => (_publicKey = key))
  }

  var privateKey = () => {
    return _privateKey
  }

  var mainKey = () => {
    return _mainKey
  }

  var publicKey = () => {
    return _publicKey
  }

  return { decryptAll, privateKey, mainKey, salt, publicKey, encPrivateKey, publicKeyId }
}

const KeySet = user => {
  var recoveryKeyString = RecoveryKey(user).get()
  var _recoveryKey = recoveryKeyString.split('-').slice(1).join('')
  var _recoveryKeyId = recoveryKeyString.split('-')[0]
  var mainKeyGenerator = MainKeyGenerator({
    recoveryKey: _recoveryKey,
    recoveryKeyId: _recoveryKeyId,
    user: user,
  })
  var salt = mainKeyGenerator.salt
  var _userKeyPromise
  var _privateKeyId = nanoid()
  var _publicKeyId = nanoid()

  var _privateKey, _publicKey, _encPrivateKey, _mainKey

  var recoveryKeyId = () => {
    return _recoveryKeyId
  }

  var recoveryKey = () => {
    return _recoveryKey
  }

  var generateUserKeys = () => {
    return UserKeyGenerator()
      .generate()
      .then(key =>
        Promise.all([
          new Promise((res, rej) => res(new Key({ key: key.privateKey, kid: _privateKey }))),
          new Promise((res, rej) => res(new Key({ key: key.publicKey, kid: _publicKeyId }))),
        ]),
      )
  }

  var generateMainKey = () => {
    return mainKeyGenerator.generate().then(key => new Key({ key, kid: 'main' }))
  }

  var exportKeyPromise = (key, kid) => {
    return new Promise((resolve, reject) => resolve(KeyExport(key.privateKey, kid)))
  }

  var generateAll = () => {
    return generateUserKeys()
      .then(keys => ([_privateKey, _publicKey] = keys))
      .then(generateMainKey)
      .then(key => (_mainKey = key))
      .then(encryptPrivateKey)
      .then(value => (_encPrivateKey = value))
      .then(() => this)
  }

  var privateKey = () => {
    return _privateKey
  }

  var publicKey = () => {
    return _publicKey
  }

  var mainKey = () => {
    return _mainKey
  }

  var encPrivateKey = () => {
    return _encPrivateKey
  }

  var encryptPrivateKey = () => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const encodedPrivateKey = textEncode(JSON.stringify(privateKey().jwk))

    return Encrypt(iv, mainKey().crypto, encodedPrivateKey)
      .then(result => bytesToBase64(new Uint8Array(result)))
      .then(data => ({
        kid: 'main',
        enc: 'A256GCM',
        cty: 'b5+jwk+json',
        iv: bytesToBase64(iv),
        data,
      }))
  }

  return {
    recoveryKey,
    recoveryKeyId,
    privateKey,
    publicKey,
    salt,
    mainKey,
    generateAll,
    encPrivateKey,
  }
}

const textEncode = string => {
  return new TextEncoder().encode(string)
}

const bytesToBase64 = bytes => {
  return sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(bytes))
}

const base64ToBytes = base64 => {
  return sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(base64))
}

const utfToBits = utf8String => {
  return sjcl.codec.utf8String.toBits(utf8String)
}

const bytesToUtf = bytes => {
  return sjcl.codec.utf8String.fromBits(sjcl.codec.bytes.toBits(bytes))
}

const bitsToHex = bits => {
  return sjcl.codec.hex.fromBits(bits)
}

const bitsToBytes = bits => {
  return sjcl.codec.bytes.fromBits(bits)
}

const hkdf = (string, string2, version = 'PBES2g-HS256') => {
  return sjcl.misc.hkdf(string, 256, string2, version, sjcl.hash.sha256)
}

const pbkdf2 = (password, salt) => {
  const importAlg = {
    name: 'PBKDF2',
  }

  const deriveAlg = {
    name: 'PBKDF2',
    salt: new Uint8Array(bitsToBytes(utfToBits(salt))),
    iterations: 100000,
    hash: { name: 'SHA-256' },
  }

  const aesOptions = {
    name: 'AES-GCM',
    length: 256,
  }

  return window.crypto.subtle
    .importKey('raw', new Uint8Array(bitsToBytes(utfToBits(password))), importAlg, false, [
      'deriveKey',
    ])
    .then(importedKey => {
      return window.crypto.subtle.deriveKey(deriveAlg, importedKey, aesOptions, true, ['encrypt'])
    })
    .then(derivedKey => {
      return window.crypto.subtle.exportKey('raw', derivedKey)
    })
    .then(res => new Uint8Array(res))
}

function xor(a, b) {
  return a.map((item, i) => item ^ b[i])
}

const RandomSalt = () => {
  var salt = window.crypto.getRandomValues(new Uint8Array(12))
  return bytesToBase64(salt)
}

const MainKeyGenerator = ({
  masterPassword = '0000',
  recoveryKey,
  recoveryKeyId,
  salt = RandomSalt(),
  user,
}) => {
  var generate = () => {
    return pbkdf2(masterPassword, bitsToHex(hkdf(utfToBits(salt), user.id))).then(pbkdf2Bytes => {
      const hkdfBytes = bitsToBytes(hkdf(utfToBits(recoveryKey), recoveryKeyId))

      const mainKeyBytes = new Uint8Array(xor(pbkdf2Bytes, hkdfBytes))

      return KeyImport(mainKeyBytes)
    })
  }

  return {
    salt,
    generate,
  }
}

const UserKeyGenerator = () => {
  var keyParams = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: {
      name: 'SHA-256',
    },
  }

  var generate = function () {
    return window.crypto.subtle.generateKey(keyParams, true, ['encrypt', 'decrypt'])
  }

  return {
    generate,
  }
}

const KeyExport = function (key, kid) {
  return window.crypto.subtle.exportKey('jwk', key).then(jwk => Object.assign(jwk, { kid }))
}

const KeyImport = function (keyBytes) {
  return window.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ])
}

const JwkImport = function (jwk) {
  var algo
  switch (jwk.alg) {
    case 'RSA-OAEP-256': {
      algo = {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-256' },
      }
      break
    }
    default: {
      algo = { name: 'AES-GCM' }
    }
  }

  return window.crypto.subtle.importKey('jwk', jwk, algo, true, jwk.key_ops)
}

const KeyGenerate = function () {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  )
}

const Encrypt = function (iv, key, data) {
  return window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    data,
  )
}

const RsaEncrypt = function (publicKey, data) {
  return window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP',
    },
    publicKey,
    data,
  )
}

const RsaDecrypt = function (privateKey, base64data) {
  return window.crypto.subtle
    .decrypt(
      {
        name: 'RSA-OAEP',
      },
      privateKey,
      new Uint8Array(base64ToBytes(base64data)).buffer,
    )
    .then(result => bytesToUtf(new Uint8Array(result)))
}

const Decrypt = function (base64iv, key, base64data) {
  return window.crypto.subtle
    .decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(base64ToBytes(base64iv)),
      },
      key,
      new Uint8Array(base64ToBytes(base64data)).buffer,
    )
    .then(result => bytesToUtf(new Uint8Array(result)))
}

const CredentialOwners = {
  PERSONAL: 'User',
  TEAM: 'Team',
}

const PrepareUserCredentials = ({ keySet, data }) => {
  console.log('PrepareUserCredentials', keySet)
  console.log('PrepareUserCredentials', data)

  const publicKey = keySet.publicKey
  const publicKeyId = keySet.publicKeyId

  return new Promise((res, rej) =>
    res(
      new Credential({ publicKey, data }).then(credential => ({
        data: credential.encrypted,
        key: credential.key.encrypted,
        publicKeyId,
      })),
    ),
  )
}

export {
  KeySet,
  RecoveryKey,
  EncryptedKeySet,
  Credential,
  EncryptedCredential,
  CredentialOwners,
  PrepareUserCredentials,
}
