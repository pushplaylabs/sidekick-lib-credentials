import { nanoid } from 'nanoid'
import * as base64Codec from './sjcl/base64.js'
import * as bytesCodec from './sjcl/bytes.js'
import * as utf8StringCodec from './sjcl/utf8String.js'
import * as hexCodec from './sjcl/hex.js'
import { HKDF } from './sjcl/hkdf.js'
import { SHA256 } from './sjcl/sha256.js'

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

  function initRecoveryKey(userId) {
    const key = `USER_${userId}`

    return {
      get: () => {
        const raw = storage.getItem(key)
        const [id, ...tail] = raw.split('-')
        return { raw, id, value: tail.join('') }
      },
      reset: () => storage.removeItem(key),
      set: raw => storage.removeItem(key, raw),
    }
  }

  function createMainKeyGenerator({
    masterPassword = '0000',
    recoveryKey,
    recoveryKeyId,
    salt = generateRandomSalt(),
    userId,
  }) {
    return {
      salt,
      generate: async () => {
        const pbkdf2Bytes = await pbkdf2(masterPassword, bitsToHex(hkdf(utfToBits(salt), userId)))
        const hkdfBytes = bitsToBytes(hkdf(utfToBits(recoveryKey), recoveryKeyId))
        const mainKeyBytes = new Uint8Array(xor(pbkdf2Bytes, hkdfBytes))

        return importKey(mainKeyBytes)
      },
    }
  }

  async function createKey({ key, kid, jwk }) {
    if (key) {
      return { crypto: key, id: kid, jwk: await exportKey(key, kid) }
    }

    return { jwk, id: jwk.kid, crypto: await importJwk(jwk) }
  }

  async function createCredentialKey({ publicKey }) {
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
      id: () => key.id,
      crypto: () => key.crypto,
    }
  }

  async function createEncryptedCredentialKey({ encryptedData, privateKey }) {
    const jwk = await decryptRSA(privateKey.crypto, encryptedData.data)
    const key = await createKey({ jwk: JSON.parse(jwk) })

    return {
      crypto: () => key.crypto,
    }
  }

  async function prepareUserCredentials({ keySet, data }) {
    const credential = await createCredential({ data, publicKey: keySet.publicKey })

    return {
      data: credential.encrypted,
      key: credential.key.encrypted,
      publicKeyId: keySet.publicKeyId,
    }
  }

  async function createCredential({ publicKey, data }) {
    const key = await createCredentialKey({ publicKey: await createKey({ jwk: publicKey }) })
    const iv = generateRandomBytes(12)
    const result = await encryptAES(iv, key.crypto(), textEncode(JSON.stringify(data)))

    return {
      key,
      encrypted: {
        kid: key.id(),
        enc: 'A256GCM',
        cty: 'b5+jwk+json',
        iv: bytesToBase64(iv),
        data: bytesToBase64(new Uint8Array(result)),
      },
    }
  }

  async function createEncryptedCredential({ encryptedData, encryptedKeyData, privateKey, id }) {
    const key = await createEncryptedCredentialKey({ encryptedData: encryptedKeyData, privateKey })
    const data = await decryptAES(encryptedData.iv, key.crypto(), encryptedData.data)

    return { id, data, encryptedData }
  }

  function createEncryptedKeySet({ userId, publicKeyRaw, publicKeyId, encryptedPrivateKey, salt }) {
    const { id: recoveryKeyId, value: recoveryKey } = initRecoveryKey(userId).get()
    const mainKeyGenerator = createMainKeyGenerator({
      recoveryKey,
      recoveryKeyId,
      userId,
      salt,
    })

    let mainKey, privateKey, publicKey

    const decryptAll = async () => {
      mainKey = await createKey({ kid: 'main', key: await mainKeyGenerator.generate() })

      const privateJwkStr = await decryptAES(
        encryptedPrivateKey.iv,
        mainKey.crypto,
        encryptedPrivateKey.data,
      )
      privateKey = await createKey({ jwk: JSON.parse(privateJwkStr) })
      publicKey = await createKey({ jwk: publicKeyRaw })
    }

    return {
      decryptAll,
      publicKeyId,
      encPrivateKey: encryptedPrivateKey,
      salt,
      mainKey: () => mainKey,
      privateKey: () => privateKey,
      publicKey: () => publicKey,
    }
  }

  async function createKeySet(userId) {
    const { id: recoveryKeyId, value: recoveryKey } = initRecoveryKey(userId).get()
    const mainKeyGenerator = createMainKeyGenerator({ recoveryKey, recoveryKeyId, userId })
    const salt = mainKeyGenerator.salt

    let privateKey, publicKey, mainKey, encPrivateKey

    const generateUserKeys = async () => {
      const key = await generateUserKey()
      const results = Promise.all([
        createKey({ key: key.privateKey, kid: privateKey }),
        createKey({ key: key.publicKey, kid: nanoid() }),
      ])
      return { privateKey: results[0], publicKey: results[1] }
    }

    const encryptPrivateKey = async () => {
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

    const generateAll = async () => {
      const userKeys = await generateUserKeys()
      privateKey = userKeys.privateKey
      publicKey = userKeys.publicKey
      mainKey = await createKey({ kid: 'main', key: await mainKeyGenerator.generate() })
      encPrivateKey = await encryptPrivateKey()
    }

    return {
      recoveryKey,
      recoveryKeyId,
      salt,
      generateAll,
      mainKey: () => mainKey,
      publicKey: () => publicKey,
      privateKey: () => privateKey,
      encPrivateKey: () => encPrivateKey,
    }
  }

  return {
    prepareUserCredentials,
    initRecoveryKey,
    createKeySet,
    createEncryptedKeySet,
    createEncryptedCredential,
    createCredential,
  }
}
