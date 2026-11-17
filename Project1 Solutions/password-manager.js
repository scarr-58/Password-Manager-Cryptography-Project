"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const SALT_LENGTH = 16;   // 128-bit salt for PBKDF2
const IV_LENGTH = 12;     // 96-bit IV, standard for AES-GCM
const CANARY_AAD = "keychain-password-check"; // used in init and load

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
    constructor(data, secrets) {
    this.data = data;       // public: kvs, salt, check (safe to dump)
    this.secrets = secrets; // private: domainKey, encKey (never dumped)
  }
    static async deriveKeys(password, salt) {
    // 1. turn the password string into a key object PBKDF2 accepts
    const pwKey = await subtle.importKey(
      "raw", stringToBuffer(password), "PBKDF2", false, ["deriveKey"]);

    // 2. the slow step: PBKDF2 gives master key k (usable as an HMAC key)
    const masterKey = await subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      pwKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"]);

    // 3. HMAC(k, label) twice gives two unrelated sub-keys
    const domainBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("domain-mac-key"));
    const encBytes = await subtle.sign("HMAC", masterKey, stringToBuffer("password-enc-key"));

    // 4. import them as real keys, each allowed to do only its own job
    const domainKey = await subtle.importKey(
      "raw", domainBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const encKey = await subtle.importKey(
      "raw", encBytes, "AES-GCM", false, ["encrypt", "decrypt"]);

    return { domainKey, encKey };
  }
 
    // Pads to exactly 64 bytes so length reveals nothing
  static pad(str) {
    const bytes = stringToBuffer(str);
    if (bytes.length > MAX_PASSWORD_LENGTH) {
      throw "Password too long";
    }
    const padded = new Uint8Array(MAX_PASSWORD_LENGTH); // starts as all zeros
    padded.set(bytes);                                  // copy password in, rest stays zero
    return padded;
  }

  // Removes the zero padding again
  static unpad(buf) {
    const bytes = new Uint8Array(buf);
    let end = bytes.length;
    while (end > 0 && bytes[end - 1] === 0) end--;
    return bufferToString(bytes.slice(0, end));
  }

  // Encrypts with AES-GCM. aad ties the ciphertext to a context (used later against swaps)
  static async encrypt(encKey, plaintext, aad) {
    const iv = getRandomBytes(IV_LENGTH);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(aad) },
      encKey, plaintext);
    const out = new Uint8Array(IV_LENGTH + ct.byteLength);
    out.set(iv, 0);                       // first 12 bytes = IV
    out.set(new Uint8Array(ct), IV_LENGTH); // the rest = ciphertext
    return encodeBuffer(out);             // one Base64 string
  }

  // Decrypts. Throws if the key or aad is wrong, or the data was changed
  static async decrypt(encKey, encoded, aad) {
    const raw = decodeBuffer(encoded);
    const iv = raw.subarray(0, IV_LENGTH);
    const ct = raw.subarray(IV_LENGTH);
    return await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: stringToBuffer(aad) },
      encKey, ct);
  }
       // Domain name -> Base64 of HMAC(domainKey, name). This is the KVS key.
  async domainTag(name) {
    const tag = await subtle.sign("HMAC", this.secrets.domainKey, stringToBuffer(name));
    return encodeBuffer(tag);
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
    static async init(password) {
    const salt = getRandomBytes(SALT_LENGTH);
    const keys = await Keychain.deriveKeys(password, salt);

    // encrypted canary: lets load() detect a wrong password
    const check = await Keychain.encrypt(keys.encKey, Keychain.pad("canary"), CANARY_AAD);

    return new Keychain(
      { kvs: {}, salt: encodeBuffer(salt), check: check },   // public
      { domainKey: keys.domainKey, encKey: keys.encKey });   // secret
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
    static async load(password, repr, trustedDataCheck) {
    // rollback defense: check the fingerprint first, if one was given
    if (trustedDataCheck !== undefined) {
      const hash = await subtle.digest("SHA-256", stringToBuffer(repr));
      if (encodeBuffer(hash) !== trustedDataCheck) {
        throw "Integrity check failed: possible tampering or rollback";
      }
    }

    const parsed = JSON.parse(repr);
    const salt = decodeBuffer(parsed.salt);
    const keys = await Keychain.deriveKeys(password, salt);

    // wrong password gives a wrong key, so the canary cannot be opened
    try {
      await Keychain.decrypt(keys.encKey, parsed.check, CANARY_AAD);
    } catch (e) {
      throw "Invalid password or corrupted keychain";
    }

    return new Keychain(
      { kvs: parsed.kvs, salt: parsed.salt, check: parsed.check },
      { domainKey: keys.domainKey, encKey: keys.encKey });
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
    async dump() {
    const repr = JSON.stringify(this.data);
    const hash = await subtle.digest("SHA-256", stringToBuffer(repr));
    return [repr, encodeBuffer(hash)];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
    async get(name) {
    const tag = await this.domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return null;   // nothing stored for this domain
    }
    // the tag is the aad: a swapped entry fails to decrypt
    let plaintext;
    try {
      plaintext = await Keychain.decrypt(this.secrets.encKey, this.data.kvs[tag], tag);
    } catch (e) {
      throw "Tampering detected: record failed authentication";
    }
    return Keychain.unpad(plaintext);
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
    async set(name, value) {
    const tag = await this.domainTag(name);
    this.data.kvs[tag] = await Keychain.encrypt(
      this.secrets.encKey, Keychain.pad(value), tag);
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
     async remove(name) {
    const tag = await this.domainTag(name);
    if (!Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      return false;  // not found
    }
    delete this.data.kvs[tag];
    return true;
  };
};

module.exports = { Keychain }
