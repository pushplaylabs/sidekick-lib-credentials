import { nanoid, customAlphabet } from 'nanoid'
import * as base64Codec from './sjcl/base64.js'
import * as bytesCodec from './sjcl/bytes.js'
import * as utf8StringCodec from './sjcl/utf8String.js'
import * as hexCodec from './sjcl/hex.js'
import { HKDF } from './sjcl/hkdf.js'
import { SHA256 } from './sjcl/sha256.js'


//------------------ MOVE TO CRYPTO WRAPPER: START ---------------------

const RSA_ALGORITHM = { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
const AES_ALGORITHM = { name: 'AES-GCM' }

/**
 * Converts Array-like object with bytes (sjcl byte array) to base64 string
 * @param {array} bytes
 * @return {string}
 */
const encode64 = (bytes) => base64Codec.fromBits(bytesCodec.toBits(bytes))

/**
 * Converts base64 string to Array-like object (sjcl byte array)
 * @param {string} base64String
 * @return {array} Array-like object (sjcl byte array)
 */
const decode64 = (base64String) =>
  bytesCodec.fromBits(base64Codec.toBits(base64String))

/**
 * Converts JSON object to Uint8Array
 * @param {object} jsonObject
 * @return {Uint8Array}
 */
const jsonToBytes = (jsonObject) =>
  (new TextEncoder()).encode(JSON.stringify(jsonObject))

/**
 * Converts Uint8Array to JSON object
 * @param {object} Uint8Array
 * @return {Uint8Array}
 */
const bytesToJSON = (bytes) => JSON.parse(bytesToUtf(bytes))

// TODO: add description
const textToBits = utf8String => utf8StringCodec.toBits(utf8String)
const bytesToUtf = bytes => utf8StringCodec.fromBits(bytesCodec.toBits(bytes))
const bitsToHex = bits => hexCodec.fromBits(bits)
const bitsToBytes = bits => bytesCodec.fromBits(bits)

/**
 * Converts string to Uint8Array
 * @param {string} text
 * @return {Uint8Array}
 */
const textToBytes = (text) => new Uint8Array(bitsToBytes(textToBits(password)))

/**
 * @param {String|bitArray} ikm - The input keying material.
 * @param {String|bitArray} salt - The salt for HKDF.
 * @return {bitArray} derived key.
 */
const hkdf = (ikm, salt) => {
  const material = typeof ikm === 'string' ? textToBits(ikm) : ikm;
  const keyBitLength = 256;
  const version = 'PBES2g-HS256';

  return HKDF(material, keyBitLength, salt, version, SHA256);
}

/**
 * xor operation for two Array-like object (sjcl byte array)
 * @param {array} a - Array-like object (sjcl byte array | Uint8Array)
 * @param {array} b - Array-like object (sjcl byte array | Uint8Array)
 * @return {array} - Array-like object
 */
const xor = (a, b) => a.map((item, i) => item ^ b[i])

/**
 * PBKDF2
 * @param {string} password
 * @param {Uint8Array} salt
 * @return {Promise} - Promise<Uint8Array> with derived key
 */
const pbkdf2 = async (password, salt) => {
  const Crypto = window.crypto.subtle
  const pwdBytes = textToBytes(password)

  const importAlg = { name: 'PBKDF2' }
  const AESOptions = { name: 'AES-GCM', length: 256 }
  const deriveAlg = {
    name: 'PBKDF2',
    iterations: 100000,
    hash: { name: 'SHA-256' },
    salt
  }

  const key = await Crypto.importKey('raw', pwdBytes, importAlg, false, ['deriveKey'])
  const derivedKey = await Crypto.deriveKey(deriveAlg, key, AESOptions, true, ['encrypt'])
  const result = await Crypto.exportKey('raw', derivedKey)

  return new Uint8Array(result)
}


// FIXME: add key type to properties
class ExtendedKey {
  constructor(options = {}) {
    this.kid = options.kid || nanoid()
    this.jwk = options.jwk
    this.crypto = options.cryptoKey
  }

  async static unpack(jwk) {
    const Crypto = window.crypto.subtle
    let algorithm = AES_ALGORITHM

    if (jwk.alg === 'RSA-OAEP-256') algorithm = RSA_ALGORITHM

    const cryptoKey = await Crypto.importKey('jwk', jwk, algorithm, true, jwk.key_ops)

    return new ExtendedKey({ cryptoKey, kid: jwk.kid, jwk })
  }

  async pack() {
    if (this.jwk) return this.jwk

    const Crypto = window.crypto.subtle
    const jwk = await Crypto.exportKey('jwk', this.crypto)
    jwk.kid = this.kid

    this.jwk = jwk

    return this.jwk
  }

  async packBytes() {
    const jwk = await this.pack()

    return jsonToBytes(jwk)
  }
}

class PublicKey {
  constructor(cryptoKey) {
    this.cryptoKey = cryptoKey
  }

  /**
   * Encrypts data with OAEP
   * @param {Uint8Array} data
   * @return {Promise} - Promise<Uint8Array> with encrypted data
   */
  async encrypt(data) {
    const algorithm = { name: 'RSA-OAEP' }
    const encrypted = await crypto.subtle.encrypt(algorithm, this.cryptoKey, data)

    return new Uint8Array(encrypted)
  }
}

class PrivateKey {
  constructor(cryptoKey) {
    this.cryptoKey = cryptoKey
    this._publicKey = null
  }

  // FIXME: crypto.subtle disallows get public key from private sync
  _setPublicKey(cryptoKey) { this._publicKey = cryptoKey }

  // FIXME: crypto.subtle disallows get public key from private sync
  _calcPublicKey() {
    const Crypto = window.crypto.subtle
    const jwk = await Crypto.exportKey("jwk", this.cryptoKey)

    // remove private data from JWK
    delete jwk.d
    delete jwk.dp
    delete jwk.dq
    delete jwk.q
    delete jwk.qi
    jwk.key_ops = ["encrypt", "wrapKey"]
    const opts = { name: "RSA-OAEP", hash: "SHA-256" }
    const keyUsages = ["encrypt", "wrapKey"]

    // import public key
    const publicKey = await Crypto.importKey("jwk", jwk, opts, true, keyUsages)

    this._setPublicKey(publicKey)
  }

  get publicKey() { return new PublicKey(this._publicKey); }

  async static generate(strength = 2048) {
    const Crypto = window.crypto.subtle
    const opts = {
      name: 'RSA-OAEP',
      modulusLength: strength,
      // FIXME: should use [1, 0, 0, 0, 1] exponent as best protected
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: {
        name: 'SHA-256',
      }
    }

    const pair = await Crypto.generateKey(opts, true, ['encrypt', 'decrypt'])
    const priv = new PrivateKey(pair.privateKey)

    // FIXME: to avoid double calculation we use public key from pair
    priv._setPublicKey(pair.publicKey)

    return priv
  }

  /**
   * Decrypts data with OAEP
   * @param {Uint8Array} encrypted - encrypted data
   * @return {Promise} - Promise<Uint8Array> with decrypted data
   */
  async decrypt(encrypted) {
    const algorithm = { name: 'RSA-OAEP' }
    const data = new Uint8Array(decode64(base64data)).buffer
    const result = await crypto.subtle.decrypt(algorithm, privateKey, data)

    return new Uint8Array(result)
  }
}

class SymmetricKey {
  constructor(options) {
    const algorithm = { name: 'AES-GCM' }

    if (options.keyBytes) this.cryptoKey = crypto.subtle.importKey(
      'raw',
      bytes,
      algorithm,
      true,
      ['encrypt', 'decrypt']
    )
    else this.cryptoKey = options.cryptoKey
  }

  async static generate() {
    const algorithm = { name: 'AES-GCM', length: 256 }
    const cryptoKey = await crypto.subtle.generateKey(algorithm, true, ['encrypt', 'decrypt'])

    return new SymmetricKey({ cryptoKey })
  }

  /**
   * Transforms data with AES cipher (GCM-mode)
   * @param {Uint8Array} data - data to transform
   * @param {Uint8Array} iv - initial vector
   * @return {Promise} - Promise<Uint8Array> with transformed data
   */
  async transform(data, iv) {
    const alg = { name: 'AES-GCM', iv }
    const transformed = await crypto.subtle.encrypt(alg, this.cryptoKey, data)

    return new Uint8Array(transformed)
  }
}

//------------------ MOVE TO CRYPTO WRAPPER: END   ---------------------

const RECOVERY_KEY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTVWXYZ'
const RECOVERY_KEY_GROUPS_COUNT = 6
const generateRecoverySixSymbols = customAlphabet(RECOVERY_KEY_ALPHABET, 6)
const generateRecoveryFiveSymbols = customAlphabet(RECOVERY_KEY_ALPHABET, 5)

export function init({ crypto = window.crypto, storage = window.localStorage } = {}) {
  const generateRandomBytes = length =>
    crypto.getRandomValues(new Uint8Array(length))

  // FIXME: there is no sense to transform salt from bytes to text and back. See usage
  const generateRandomSalt = () => encode64(generateRandomBytes(12))

  const encryptPrivateKey = async (mainKeyDeprecated, privateKeyDeprecated) => {
    const iv = generateRandomBytes(12)
    const sk = new SymmetricKey({ cryptoKey: mainKeyDeprecated.crypto })

    const privateKeyPacked = jsonToBytes(privateKeyDeprecated.jwk)
    const privateKeyTransformed = sk.transform(privateKeyPacked, iv)

    return {
      kid: 'main',
      enc: 'A256GCM',
      cty: 'b5+jwk+json',
      iv: encode64(iv),
      data: encode64(privateKeyTransformed),
    }
  }

  const recoveryKeyManager = (() => {
    const getKey = userId => `USER_${userId}`
    const extractData = raw => {
      const [id, ...tail] = raw.split('-')
      return { raw, id, value: tail.join('') }
    }

    return {
      get: userId => {
        const raw = storage.getItem(getKey(userId))
        return raw ? extractData(raw) : null
      },
      generate: () => {
        const result = []
        for (let i = 0; i < RECOVERY_KEY_GROUPS_COUNT; i += 1) {
          result.push(i < 2 ? generateRecoverySixSymbols() : generateRecoveryFiveSymbols())
        }
        return extractData(result.join('-'))
      },
      reset: userId => storage.removeItem(getKey(userId)),
      set: (userId, raw) => storage.setItem(getKey(userId), raw),
    }
  })()

  async function recoverMainKey({
    masterPassword = '0000',
    recoveryKey,
    salt,
    userId
  }) {
    // FIXME: salt should be just random bytes
    const complexSalt = textToBytes(bitsToHex(hkdf(textToBits(salt), userId)))
    const derivedKey = await pbkdf2(masterPassword, complexSalt)
    const hkdfBits = hkdf(textToBits(recoveryKey.value), recoveryKey.id)
    const hkdfBytes = bitsToBytes(hkdfBits)
    const mainKeyBytes = new Uint8Array(xor(derivedKey, hkdfBytes))

    return new SymmetricKey({ keyBytes: mainKeyBytes })
  }

  async function prepareUserCredentials({ keySet, data }) {
    const credential = await encryptCredential({ data, publicKey: keySet.publicKey })

    return {
      data: credential.encrypted,
      key: credential.key.encrypted,
      publicKeyId: keySet.publicKeyId,
    }
  }

  async function encryptCredential(options) {
    const data = options.data
    const publicKeyExt = await ExtendedKey.unpack(options.publicKey)
    const publicKey = new PublicKey(publicKeyExt.crypto)
    const symmetricKey = await SymmetricKey.generate()
    const symmetricKeyExt = new ExtendedKey({ cryptoKey: symmetricKey.cryptoKey })

    const packed = await symmetricKeyExt.packBytes()
    const encrypted = publicKey.encrypt(packed)

    const iv = generateRandomBytes(12)
    const transformed = symmetricKey.transform(jsonToBytes(data), iv)

    return {
      key: {
        encrypted: {
          kid: publicKeyExt.id,
          enc: 'RSA-OAEP',
          cty: 'b5+jwk+json',
          data: encode64(encrypted),
        },
        id: symmetricKeyExt.id,
        crypto: symmetricKeyExt.crypto,
      },
      encrypted: {
        kid: symmetricKeyExt.id,
        enc: 'A256GCM',
        cty: 'b5+jwk+json',
        iv: encode64(iv),
        data: encode64(transformed),
      },
    }
  }

  async function decryptCredential({
    encryptedData,
    encryptedKeyData,
    privateKey
  }) {
    const encryptedData = options.encryptedData
    const encryptedKeyData = options.encryptedKeyData
    const privateKeyPacked = options.privateKey

    const privateKey = new PrivateKey(privateKeyPacked.crypto)

    const encryptedSymmetricKeyJWK = new Uint8Array(decode64(encryptedKeyData.data))
    const symmetricKeyJWKBytes = privateKey.decrypt(encryptedSymmetricKeyJWK)
    const symmetricKeyJWK = bytesToJSON(symmetricKeyJWKBytes)
    const symmetricKeyExt = await ExtendedKey.unpack(symmetricKeyJWK)

    const symmetricKey = new SymmetricKey({ key: symmetricKeyExt.crypto })

    const data = await symmetricKey.transform(encryptedData.data, encryptedData.iv)

    return bytesToJSON(data)
  }

  async function decryptKeySet({
    userId,
    recoveryKey,
    publicKeyRaw,
    encryptedPrivateKey,
    salt
  }) {
    const symmetricKey = await recoverMainKey({ userId, recoveryKey, salt })
    const symmetricKeyExt = new ExtendedKey({ kid: 'main', cryptoKey: symmetricKey.cryptoKey })
    await symmetricKeyExt.pack()

    const privateJWKBytes = await symmetricKey.transform(
      encryptedPrivateKey.data,
      encryptedPrivateKey.iv
    )

    const privateJWK = JSON.parse(bytesToUtf(privateJWKBytes))
    const privateKeyExt = await ExtendedKey.unpack(privateJWKBytes)
    // FIXME: is public key related to provided private? should calculate public from private
    const publicKeyExt = await ExtendedKey.unpack(publicKeyRaw)

    return {
      mainKey: symmetricKeyExt,
      privateKey: privateKeyExt,
      publicKey: publicKeyExt,
    }
  }

  async function createKeySet({ userId, recoveryKey }) {
    const salt = generateRandomSalt()
    const sk = await recoverMainKey({ userId, recoveryKey, salt })
    const priv = await PrivateKey.generate()
    const pub = priv.publicKey

    const mainKey = new ExtendedKey({ kid: 'main', cryptoKey: sk.cryptoKey })
    const privateKey = new ExtendedKey({ cryptoKey: priv.cryptoKey })
    const publicKey = new ExtendedKey({ cryptoKey: pub.cryptoKey })

    // FIXME: we called pack to make sure 'jwk' property is calculated for sync access.
    // Should use pack() when jwk is needed
    await mainKey.pack()
    await privateKey.pack()
    await publicKey.pack()

    return {
      salt,
      mainKey,
      publicKey,
      privateKey,
    }
  }

  return {
    recoveryKeyManager,
    createKeySet,
    decryptKeySet,
    encryptCredential,
    decryptCredential,
    encryptPrivateKey,
    prepareUserCredentials,
  }
}
