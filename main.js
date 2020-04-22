import { nanoid, customAlphabet } from 'nanoid'
import * as base64Codec from './sjcl/base64.js'
import * as bytesCodec from './sjcl/bytes.js'
import * as utf8StringCodec from './sjcl/utf8String.js'
import * as hexCodec from './sjcl/hex.js'
import { HKDF } from './sjcl/hkdf.js'
import { SHA256 } from './sjcl/sha256.js'

const RECOVERY_KEY_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTVWXYZ'
const RECOVERY_KEY_GROUPS_COUNT = 6
const generateRecoverySixSymbols = customAlphabet(RECOVERY_KEY_ALPHABET, 6)
const generateRecoveryFiveSymbols = customAlphabet(RECOVERY_KEY_ALPHABET, 5)

const textEncode = string => new TextEncoder().encode(string)
const bytesToBase64 = bytes => base64Codec.fromBits(bytesCodec.toBits(bytes))
const base64ToBytes = base64 => bytesCodec.fromBits(base64Codec.toBits(base64))
const utfToBits = utf8String => utf8StringCodec.toBits(utf8String)
const bytesToUtf = bytes => utf8StringCodec.fromBits(bytesCodec.toBits(bytes))
const bitsToHex = bits => hexCodec.fromBits(bits)
const bitsToBytes = bits => bytesCodec.fromBits(bits)
const hkdf = (string, string2, version = 'PBES2g-HS256') =>
  HKDF(string, 256, string2, version, SHA256)

function xor(a, b) {
  return a.map((item, i) => item ^ b[i])
}

export const CredentialOwners = Object.freeze({
  PERSONAL: 'User',
  TEAM: 'Team',
})

export function init({ crypto = window.crypto, storage = window.localStorage } = {}) {
  const pbkdf2 = async (password, saltStr) => {
    const importAlg = { name: 'PBKDF2' }
    const passwordRaw = new Uint8Array(bitsToBytes(utfToBits(password)))
    const key = await crypto.subtle.importKey('raw', passwordRaw, importAlg, false, ['deriveKey'])

    const salt = new Uint8Array(bitsToBytes(utfToBits(saltStr)))
    const deriveAlg = { name: 'PBKDF2', iterations: 100000, hash: { name: 'SHA-256' }, salt }
    const aesOptions = { name: 'AES-GCM', length: 256 }
    const derivedKey = await crypto.subtle.deriveKey(deriveAlg, key, aesOptions, true, ['encrypt'])

    const result = await crypto.subtle.exportKey('raw', derivedKey)
    return new Uint8Array(result)
  }

  const generateUserKey = () => {
    const algorithm = {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: {
        name: 'SHA-256',
      },
    }

    return crypto.subtle.generateKey(algorithm, true, ['encrypt', 'decrypt'])
  }

  const generateUserKeys = async () => {
    const key = await generateUserKey()
    const [privateKey, publicKey] = await Promise.all([
      createKey({ key: key.privateKey, kid: nanoid() }),
      createKey({ key: key.publicKey, kid: nanoid() }),
    ])
    return { privateKey, publicKey }
  }

  const exportKey = async (key, kid) => {
    const jwk = await crypto.subtle.exportKey('jwk', key)
    return Object.assign(jwk, { kid })
  }

  const importKey = keyBytes => {
    const algorithm = { name: 'AES-GCM' }
    return crypto.subtle.importKey('raw', keyBytes, algorithm, true, ['encrypt', 'decrypt'])
  }

  const getAlgorightByName = name => {
    switch (name) {
      case 'RSA-OAEP-256': {
        return { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
      }
      default: {
        return { name: 'AES-GCM' }
      }
    }
  }

  const importJwk = jwk =>
    crypto.subtle.importKey('jwk', jwk, getAlgorightByName(jwk.alg), true, jwk.key_ops)

  const generateRandomBytes = length => crypto.getRandomValues(new Uint8Array(length))

  const generateKey = () => {
    const algorithm = { name: 'AES-GCM', length: 256 }
    return crypto.subtle.generateKey(algorithm, true, ['encrypt', 'decrypt'])
  }

  const encryptAES = (iv, key, data) => {
    const algorithm = { name: 'AES-GCM', iv }
    return crypto.subtle.encrypt(algorithm, key, data)
  }

  const encryptRSA = (publicKey, data) => {
    const algorithm = { name: 'RSA-OAEP' }
    return crypto.subtle.encrypt(algorithm, publicKey, data)
  }

  const decryptAES = async (base64iv, key, base64data) => {
    const iv = new Uint8Array(base64ToBytes(base64iv))
    const algorithm = { name: 'AES-GCM', iv }
    const data = new Uint8Array(base64ToBytes(base64data)).buffer
    const result = await crypto.subtle.decrypt(algorithm, key, data)

    return bytesToUtf(new Uint8Array(result))
  }

  const decryptRSA = async (privateKey, base64data) => {
    const algorithm = { name: 'RSA-OAEP' }
    const data = new Uint8Array(base64ToBytes(base64data)).buffer
    const result = await crypto.subtle.decrypt(algorithm, privateKey, data)

    return bytesToUtf(new Uint8Array(result))
  }

  const generateRandomSalt = () => bytesToBase64(generateRandomBytes(12))

  const encryptPrivateKey = async (mainKey, privateKey) => {
    const iv = generateRandomBytes(12)
    const encodedPrivateKey = textEncode(JSON.stringify(privateKey.jwk))

    const result = await encryptAES(iv, mainKey.crypto, encodedPrivateKey)
    const data = bytesToBase64(new Uint8Array(result))

    return {
      kid: 'main',
      enc: 'A256GCM',
      cty: 'b5+jwk+json',
      iv: bytesToBase64(iv),
      data,
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

  async function generateMainKey({ masterPassword = '0000', recoveryKey, salt, userId }) {
    const pbkdf2Bytes = await pbkdf2(masterPassword, bitsToHex(hkdf(utfToBits(salt), userId)))
    const hkdfBytes = bitsToBytes(hkdf(utfToBits(recoveryKey.value), recoveryKey.id))
    const mainKeyBytes = new Uint8Array(xor(pbkdf2Bytes, hkdfBytes))

    return importKey(mainKeyBytes)
  }

  async function createKey({ key, kid, jwk }) {
    if (key) {
      return { crypto: key, id: kid, jwk: await exportKey(key, kid) }
    }

    return { jwk, id: jwk.kid, crypto: await importJwk(jwk) }
  }

  async function encryptCredentialKey({ publicKey }) {
    const key = await createKey({ key: await generateKey(), kid: nanoid() })
    const encodedKey = textEncode(JSON.stringify(key.jwk))

    const result = await encryptRSA(publicKey.crypto, encodedKey)
    const data = bytesToBase64(new Uint8Array(result))

    return {
      encrypted: {
        kid: publicKey.id,
        enc: 'RSA-OAEP',
        cty: 'b5+jwk+json',
        data,
      },
      id: key.id,
      crypto: key.crypto,
    }
  }

  async function decryptCredentialKey({ encryptedData, privateKey }) {
    const jwk = await decryptRSA(privateKey.crypto, encryptedData.data)
    const key = await createKey({ jwk: JSON.parse(jwk) })

    return {
      crypto: key.crypto,
    }
  }

  async function prepareUserCredentials({ keySet, data }) {
    const credential = await encryptCredential({ data, publicKey: keySet.publicKey })

    return {
      data: credential.encrypted,
      key: credential.key.encrypted,
      publicKeyId: keySet.publicKeyId,
    }
  }

  async function encryptCredential({ publicKey, data }) {
    const key = await encryptCredentialKey({ publicKey: await createKey({ jwk: publicKey }) })
    const iv = generateRandomBytes(12)
    const result = await encryptAES(iv, key.crypto, textEncode(JSON.stringify(data)))

    return {
      key,
      encrypted: {
        kid: key.id,
        enc: 'A256GCM',
        cty: 'b5+jwk+json',
        iv: bytesToBase64(iv),
        data: bytesToBase64(new Uint8Array(result)),
      },
    }
  }

  async function decryptCredential({ encryptedData, encryptedKeyData, privateKey }) {
    const key = await decryptCredentialKey({ encryptedData: encryptedKeyData, privateKey })
    const data = await decryptAES(encryptedData.iv, key.crypto, encryptedData.data)
    return JSON.parse(data)
  }

  async function decryptKeySet({ userId, recoveryKey, publicKeyRaw, encryptedPrivateKey, salt }) {
    const mainKey = await createKey({
      kid: 'main',
      key: await generateMainKey({ userId, recoveryKey, salt }),
    })

    const privateJwkStr = await decryptAES(
      encryptedPrivateKey.iv,
      mainKey.crypto,
      encryptedPrivateKey.data,
    )
    const [privateKey, publicKey] = await Promise.all([
      createKey({ jwk: JSON.parse(privateJwkStr) }),
      createKey({ jwk: publicKeyRaw }),
    ])

    return {
      mainKey,
      privateKey,
      publicKey,
    }
  }

  async function createKeySet({ userId, recoveryKey }) {
    const salt = generateRandomSalt()
    const [mainKey, { publicKey, privateKey }] = await Promise.all([
      Promise.resolve()
        .then(() => generateMainKey({ userId, recoveryKey, salt }))
        .then(key => createKey({ kid: 'main', key })),
      generateUserKeys(),
    ])

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
