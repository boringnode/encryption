/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
import { MessageBuilder, type Secret } from '@poppinss/utils'
import { BaseDriver } from './base_driver.ts'
import { Hmac } from '../hmac.ts'
import * as errors from '../exceptions.ts'
import type {
  AES256CBCConfig,
  CypherText,
  EncryptionConfig,
  EncryptionDriverContract,
} from '../types/main.ts'
import { base64UrlDecode, base64UrlEncode } from '../base64.ts'

export interface AES256CBCDriverConfig {
  id: string
  keys: (string | Secret<string>)[]
}

export function aes256cbc(config: AES256CBCDriverConfig) {
  return {
    driver: (key) => new AES256CBC({ id: config.id, key }),
    keys: config.keys,
  } satisfies EncryptionConfig
}

export class AES256CBC extends BaseDriver implements EncryptionDriverContract {
  #config: AES256CBCConfig

  constructor(config: AES256CBCConfig) {
    super(config)

    this.#config = config

    if (typeof config.id !== 'string') {
      throw new errors.E_MISSING_ENCRYPTER_ID()
    }
  }

  /**
   * Encrypt a given piece of value using the app secret. A wide range of
   * data types are supported.
   *
   * - String
   * - Arrays
   * - Objects
   * - Booleans
   * - Numbers
   * - Dates
   *
   * You can optionally define a purpose for which the value was encrypted and
   * mentioning a different purpose/no purpose during decrypt will fail.
   */
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = randomBytes(16)

    const { encryptionKey, authenticationKey } = this.#deriveKey(this.cryptoKey, iv)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv('aes-256-cbc', encryptionKey, iv)

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const plainText = new MessageBuilder().build(payload, expiresIn, purpose)

    /**
     * Set final to the cipher instance and encrypt it
     */
    const cipherText = Buffer.concat([cipher.update(plainText), cipher.final()])

    /**
     * Concatenate `encrypted value` and `iv` by urlEncoding them. The concatenation is required
     * to generate the HMAC, so that HMAC checks for integrity of both the `encrypted value`
     * and the `iv`.
     */
    const macPayload = `${base64UrlEncode(cipherText)}${this.separator}${base64UrlEncode(iv)}`

    /**
     * Returns the id + result + hmac
     */
    const hmac = new Hmac(authenticationKey).generate(macPayload)
    return this.computeReturns([this.#config.id, macPayload, hmac])
  }

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null {
    if (typeof value !== 'string') {
      return null
    }

    /**
     * Make sure the encrypted value is in the correct format.
     * i.e.: [id].[encrypted value].[iv].[mac]
     */
    const [id, cipherEncoded, ivEncoded, macEncoded] = value.split(this.separator)
    if (!id || !cipherEncoded || !ivEncoded || !macEncoded) {
      return null
    }

    /**
     * Make sure the id is correct
     */
    if (id !== this.#config.id) {
      return null
    }

    /**
     * Make sure we are able to decode the encrypted value
     */
    const cipherText = base64UrlDecode(cipherEncoded)
    if (!cipherText) {
      return null
    }

    /**
     * Make sure we are able to decode the iv
     */
    const iv = base64UrlDecode(ivEncoded)
    if (!iv) {
      return null
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    const { encryptionKey, authenticationKey } = this.#deriveKey(this.cryptoKey, iv)

    const isValidHmac = new Hmac(authenticationKey).compare(
      `${cipherEncoded}${this.separator}${ivEncoded}`,
      macEncoded
    )

    if (!isValidHmac) {
      return null
    }

    /**
     * The Decipher can raise exceptions with malformed input, so we wrap it
     * to avoid leaking sensitive information
     */
    try {
      const decipher = createDecipheriv('aes-256-cbc', encryptionKey, iv)
      const plainTextBuffer = Buffer.concat([decipher.update(cipherText), decipher.final()])
      return new MessageBuilder().verify(plainTextBuffer, purpose)
    } catch {
      return null
    }
  }

  #deriveKey(masterKey: Buffer, iv: Buffer) {
    const info = Buffer.from(this.#config.id)
    const rawDerivedKey = hkdfSync('sha256', masterKey, iv, info, 64)

    const derivedKey = Buffer.isBuffer(rawDerivedKey) ? rawDerivedKey : Buffer.from(rawDerivedKey)

    return {
      encryptionKey: derivedKey.subarray(0, 32),
      authenticationKey: derivedKey.subarray(32),
    }
  }
}
