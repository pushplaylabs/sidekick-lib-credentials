/**
 * @fileOverview HKDF implementation.
 *
 * @author Steve Thomas
 */
import * as bitArray from './bitArray.js'
import * as utf8StringCodec from './utf8String.js'
import { HMAC } from './hmac.js'
import { SHA256 } from './sha256.js'

/** HKDF with the specified hash function.
 * @param {bitArray} ikm The input keying material.
 * @param {Number} keyBitLength The output key length, in bits.
 * @param {String|bitArray} salt The salt for HKDF.
 * @param {String|bitArray} info The info for HKDF.
 * @param {Object} [Hash=SHA256] The hash function to use.
 * @return {bitArray} derived key.
 */
export function HKDF(ikm, keyBitLength, salt, info, Hash) {
  var hmac,
    key,
    i,
    hashLen,
    loops,
    curOut,
    ret = []

  Hash = Hash || SHA256
  if (typeof info === 'string') {
    info = utf8StringCodec.toBits(info)
  }
  if (typeof salt === 'string') {
    salt = utf8StringCodec.toBits(salt)
  } else if (!salt) {
    salt = []
  }

  hmac = new HMAC(salt, Hash)
  key = hmac.mac(ikm)
  hashLen = bitArray.bitLength(key)

  loops = Math.ceil(keyBitLength / hashLen)
  if (loops > 255) {
    throw new TypeError('key bit length is too large for hkdf')
  }

  hmac = new HMAC(key, Hash)
  curOut = []
  for (i = 1; i <= loops; i++) {
    hmac.update(curOut)
    hmac.update(info)
    hmac.update([bitArray.partial(8, i)])
    curOut = hmac.digest()
    ret = bitArray.concat(ret, curOut)
  }
  return bitArray.clamp(ret, keyBitLength)
}
