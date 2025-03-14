/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv } from 'node:crypto'
import string from '@poppinss/utils/string'
import { base64, MessageBuilder } from '@poppinss/utils'
import { BaseDriver } from './base_driver.js'
import { Hmac } from '../hmac.js'
import type { EncryptionDriverContract, LegacyConfig } from '../types/main.js'

/**
 * This driver was mainly created to maintain compatibility
 * with the existing encryption module of AdonisJS.
 */
export class Legacy extends BaseDriver implements EncryptionDriverContract {
  /**
   * Reference to base64 object for base64 encoding/decoding values
   */
  base64: typeof base64 = base64

  constructor(config: LegacyConfig) {
    super(config)
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string) {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = string.random(16)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv('aes-256-cbc', this.getFirstKey().key, iv)

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const encodedValue = new MessageBuilder().build(payload, expiresIn, purpose)

    /**
     * Set final to the cipher instance and encrypt it
     */
    const encrypted = Buffer.concat([cipher.update(encodedValue, 'utf-8'), cipher.final()])

    /**
     * Concatenate `encrypted value` and `iv` by urlEncoding them. The concatenation is required
     * to generate the HMAC, so that HMAC checks for integrity of both the `encrypted value`
     * and the `iv`.
     */
    const result = `${this.base64.urlEncode(encrypted)}${this.separator}${this.base64.urlEncode(
      iv
    )}`

    /**
     * Returns the result + hmac
     */
    const hmac = new Hmac(this.getFirstKey().key).generate(result)
    return this.computeReturns([result, hmac])
  }

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null {
    if (typeof value !== 'string') {
      return null
    }

    /**
     * Make sure the encrypted value is in correct format. ie
     * [encrypted value].[iv].[hash]
     */
    const [encryptedEncoded, ivEncoded, hash] = value.split(this.separator)
    if (!encryptedEncoded || !ivEncoded || !hash) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the encrypted value
     */
    const encrypted = this.base64.urlDecode(encryptedEncoded, 'base64')
    if (!encrypted) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the iv
     */
    const iv = this.base64.urlDecode(ivEncoded)
    if (!iv) {
      return null
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    for (const { key } of this.cryptoKeys) {
      const isValidHmac = new Hmac(key).compare(
        `${encryptedEncoded}${this.separator}${ivEncoded}`,
        hash
      )

      if (!isValidHmac) {
        continue
      }

      /**
       * The Decipher can raise exceptions with malformed input, so we wrap it
       * to avoid leaking sensitive information
       */
      try {
        const decipher = createDecipheriv('aes-256-cbc', key, iv)
        const decrypted = decipher.update(encrypted, 'base64', 'utf8') + decipher.final('utf8')

        return new MessageBuilder().verify(decrypted, purpose)
      } catch {}
    }

    return null
  }
}
