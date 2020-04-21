/**
 * @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
import { SHA256 } from './sha256.js'

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [Hash=SHA256] The hash function to use.
 */
export class HMAC {
  constructor(key, Hash) {
    this.mac = this.encrypt
    this._hash = Hash = Hash || SHA256
    var exKey = [[], []],
      i,
      bs = Hash.prototype.blockSize / 32
    this._baseHash = [new Hash(), new Hash()]

    if (key.length > bs) {
      key = Hash.hash(key)
    }

    for (i = 0; i < bs; i++) {
      exKey[0][i] = key[i] ^ 0x36363636
      exKey[1][i] = key[i] ^ 0x5c5c5c5c
    }

    this._baseHash[0].update(exKey[0])
    this._baseHash[1].update(exKey[1])
    this._resultHash = new Hash(this._baseHash[0])
  }

  /** HMAC with the specified hash function.  Also called encrypt since it's a prf.
   * @param {bitArray|String} data The data to mac.
   */
  encrypt(data) {
    if (!this._updated) {
      this.update(data)
      return this.digest(data)
    } else {
      throw new TypeError('encrypt on already updated hmac called!')
    }
  }

  reset() {
    this._resultHash = new this._hash(this._baseHash[0])
    this._updated = false
  }

  update(data) {
    this._updated = true
    this._resultHash.update(data)
  }

  digest() {
    var w = this._resultHash.finalize(),
      result = new this._hash(this._baseHash[1]).update(w).finalize()

    this.reset()

    return result
  }
}
