const chai = require('chai');
const expect = chai.expect;

import { init } from '../main';

const {
  recoveryKeyManager,
  createKeySet,
  decryptKeySet,
  encryptCredential,
  decryptCredential,
  encryptPrivateKey,
  prepareUserCredentials
} = init();

const USER_ID = "123";
const USER_STORAGE_KEY = `USER_${USER_ID}`;
const RECOVERY_KEY1 = { raw: "KSKC39-SYC4XS-BP9FR-G84HB-RVV46-2VV68", id: "KSKC39", value: "SYC4XSBP9FRG84HBRVV462VV68" };

describe("Crypto", () => {
  describe("KeySet", () => {
    it('should create key set', async () => {
      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const { mainKey, privateKey, publicKey } = keySet;

      expect(keySet.salt).to.be.a("string");

      expect(mainKey.crypto).to.be.an.instanceof(CryptoKey);
      expect(privateKey.crypto).to.be.an.instanceof(CryptoKey);
      expect(publicKey.crypto).to.be.an.instanceof(CryptoKey);

      // main key

      expect(mainKey.crypto.algorithm.name).to.equal("AES-GCM");
      expect(mainKey.crypto.algorithm.length).to.equal(256);
      expect(mainKey.crypto.type).to.equal("secret");
      expect(mainKey.crypto.extractable).to.equal(true);
      expect(mainKey.id).to.equal("main");
      expect(mainKey.jwk.alg).to.equal("A256GCM");
      expect(mainKey.jwk.k).to.equal("8PP7Bjf9h7_94nN3mogn9LSmA-9ZKlx0YIl5duBXDnU");
      expect(mainKey.jwk.kid).to.equal("main");

      // private key

      expect(privateKey.crypto.algorithm.name).to.equal("RSA-OAEP");
      expect(privateKey.crypto.algorithm.modulusLength).to.equal(2048);
      expect(privateKey.crypto.type).to.equal("private");
      expect(privateKey.crypto.extractable).to.equal(true);
      expect(privateKey.id).to.be.a("string");
      expect(privateKey.id.length).to.equal(21);
      expect(privateKey.jwk.alg).to.equal("RSA-OAEP-256");
      expect(privateKey.jwk.kid).to.equal(privateKey.id);

      // public key

      expect(publicKey.crypto.algorithm.name).to.equal("RSA-OAEP");
      expect(publicKey.crypto.algorithm.modulusLength).to.equal(2048);
      expect(publicKey.crypto.type).to.equal("public");
      expect(publicKey.crypto.extractable).to.equal(true);
      expect(publicKey.id).to.be.a("string");
      expect(publicKey.id.length).to.equal(21);
      expect(publicKey.jwk.alg).to.equal("RSA-OAEP-256");
      expect(publicKey.jwk.kid).to.equal(publicKey.id);
    });

    it('should encrypt private key', async () => {
      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const encrypted = await encryptPrivateKey(keySet.mainKey, keySet.privateKey);

      expect(encrypted.cty).to.equal("b5+jwk+json");
      expect(encrypted.enc).to.equal("A256GCM");
      expect(encrypted.kid).to.equal("main");
      expect(encrypted.data).to.be.a("string");
      expect(encrypted.iv).to.be.a("string");
    });

    it('should decrypt key set', async () => {
      // const encryptedPrivateKey = {
      //   cty: "b5+jwk+json",
      //   data: "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",
      //   enc: "A256GCM",
      //   iv: "tRPeJ4h3xKgZPOkN",
      //   kid: "main"
      // };

      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const encryptedPrivateKey = await encryptPrivateKey(keySet.mainKey, keySet.privateKey);

      const keySet2 = await decryptKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1,
        publicKeyRaw: keySet.publicKey.jwk,
        encryptedPrivateKey,
        salt: keySet.salt
      });

      const { mainKey, privateKey, publicKey } = keySet2;

      // FIXME: should be salt always
      // expect(keySet2.salt).to.be.a("string");

      expect(mainKey.crypto).to.be.an.instanceof(CryptoKey);
      expect(privateKey.crypto).to.be.an.instanceof(CryptoKey);
      expect(publicKey.crypto).to.be.an.instanceof(CryptoKey);

      // main key

      expect(mainKey.crypto.algorithm.name).to.equal("AES-GCM");
      expect(mainKey.crypto.algorithm.length).to.equal(256);
      expect(mainKey.crypto.type).to.equal("secret");
      expect(mainKey.crypto.extractable).to.equal(true);
      expect(mainKey.id).to.equal("main");
      expect(mainKey.jwk.alg).to.equal("A256GCM");
      expect(mainKey.jwk.k).to.equal("8PP7Bjf9h7_94nN3mogn9LSmA-9ZKlx0YIl5duBXDnU");
      expect(mainKey.jwk.kid).to.equal("main");

      // private key

      expect(privateKey.crypto.algorithm.name).to.equal("RSA-OAEP");
      expect(privateKey.crypto.algorithm.modulusLength).to.equal(2048);
      expect(privateKey.crypto.type).to.equal("private");
      expect(privateKey.crypto.extractable).to.equal(true);
      expect(privateKey.id).to.be.a("string");
      expect(privateKey.id.length).to.equal(21);
      expect(privateKey.jwk.alg).to.equal("RSA-OAEP-256");
      expect(privateKey.jwk.kid).to.equal(privateKey.id);

      // public key

      expect(publicKey.crypto.algorithm.name).to.equal("RSA-OAEP");
      expect(publicKey.crypto.algorithm.modulusLength).to.equal(2048);
      expect(publicKey.crypto.type).to.equal("public");
      expect(publicKey.crypto.extractable).to.equal(true);
      expect(publicKey.id).to.be.a("string");
      expect(publicKey.id.length).to.equal(21);
      expect(publicKey.jwk.alg).to.equal("RSA-OAEP-256");
      expect(publicKey.jwk.kid).to.equal(publicKey.id);
    });
  });

  describe("Credentials", () => {
    it('should encrypt credential', async () => {
      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const encryptedCredential = await encryptCredential({
        publicKey: keySet.publicKey.jwk,
        data: { username: "john", password: "doe" }
      });

      const { encrypted, key } = encryptedCredential;

      expect(encrypted.kid).to.equal(key.id);

      expect(encrypted.cty).to.equal("b5+jwk+json");
      expect(encrypted.data).to.be.a("string");
      expect(encrypted.iv).to.be.a("string");
      expect(encrypted.kid).to.be.a("string");
      expect(encrypted.enc).to.equal("A256GCM");

      expect(key.crypto).to.be.an.instanceof(CryptoKey);
      expect(key.crypto.algorithm.name).to.equal("AES-GCM");
      expect(key.crypto.type).to.equal("secret");
      expect(key.encrypted.cty).to.equal("b5+jwk+json");
      expect(key.encrypted.data).to.be.a("string");
      expect(key.encrypted.enc).to.equal("RSA-OAEP");
      expect(key.encrypted.kid).to.be.a("string");
    });

    it('should decrypt credential', async () => {
      const data = { mySecretData: { username: "john", password: "doe" } };

      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const encryptedCredential = await encryptCredential({
        publicKey: keySet.publicKey.jwk,
        data
      });

      const { encrypted, key } = encryptedCredential;

      const decrypted = await decryptCredential({
        encryptedData: encrypted,
        encryptedKeyData: key.encrypted,
        privateKey: keySet.privateKey
      });

      expect(decrypted).to.deep.equal(data);
    });

    it('should prepare user credentials', async () => {
      const keySet = await createKeySet({
        userId: USER_ID,
        recoveryKey: RECOVERY_KEY1
      });

      const data = { mySecretData: { username: "john", password: "doe" } };

      // FIXME: Broken key set
      // keySet.publicKeyId is undefined
      keySet.publicKey = keySet.publicKey.jwk;

      const encrypted = await prepareUserCredentials({ keySet, data });

      expect(encrypted).has.all.keys("data", "key", "publicKeyId");
    });
  });

  describe("RecoveryKeyManager", () => {

    it('should generate valid recovery key', async () => {
      const RECOVERY_FORMAT = /^[2-9A-Z]{6}-[2-9A-Z]{6}-[2-9A-Z]{5}-[2-9A-Z]{5}-[2-9A-Z]{5}-[2-9A-Z]{5}$/;

      const key = recoveryKeyManager.generate();
      const clearKey = key.raw.split("-").join("");

      expect(RECOVERY_FORMAT.test(key.raw)).to.equal(true);
      expect(key.id + key.value).to.equal(clearKey);
    });

    it('should set key to storage', async () => {
      localStorage.removeItem(USER_STORAGE_KEY);
      recoveryKeyManager.set(USER_ID, RECOVERY_KEY1.raw);
      const storageValue = localStorage.getItem(USER_STORAGE_KEY);

      localStorage.removeItem(USER_STORAGE_KEY);

      expect(storageValue).to.equal(RECOVERY_KEY1.raw);
    });

    it('should get key from storage', async () => {
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.setItem(USER_STORAGE_KEY, RECOVERY_KEY1.raw);

      const key = recoveryKeyManager.get(USER_ID);

      localStorage.removeItem(USER_STORAGE_KEY);

      expect(key.raw).to.equal(RECOVERY_KEY1.raw);
      expect(key.id).to.equal(RECOVERY_KEY1.id);
      expect(key.value).to.equal(RECOVERY_KEY1.value);
    });

    it('should remove key from storage', async () => {
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.setItem(USER_STORAGE_KEY, RECOVERY_KEY1.raw);

      recoveryKeyManager.reset(USER_ID);

      const storageValue = localStorage.getItem(USER_STORAGE_KEY);

      expect(storageValue).to.be.a('null');
    });
  });
});
