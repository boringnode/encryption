/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { MessageBuilder } from '@poppinss/utils'
import { BaseDriver } from './base_driver.ts'
import { Hmac } from '../hmac.ts'
import type { EncryptionDriverContract, LegacyConfig } from '../types/main.ts'
import { base64UrlDecode, base64UrlEncode } from '../base64.ts'

/**
 * This driver was mainly created to maintain compatibility
 * with the existing encryption module of AdonisJS.
 */
export class Legacy extends BaseDriver implements EncryptionDriverContract {
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
    const iv = randomBytes(16)

    /**
     * Creating chiper
     */
    const cipher = createCipheriv('aes-256-cbc', this.getFirstKey().key, iv)

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
     * Returns the result + hmac
     */
    const hmac = new Hmac(this.getFirstKey().key).generate(macPayload)
    return this.computeReturns([macPayload, hmac])
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
     * i.e.: [encrypted value].[iv].[mac]
     */
    const [cipherEncoded, ivEncoded, macEncoded] = value.split(this.separator)
    if (!cipherEncoded || !ivEncoded || !macEncoded) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the encrypted value
     */
    const cipherText = base64UrlDecode(cipherEncoded)
    if (!cipherText) {
      return null
    }

    /**
     * Make sure we are able to urlDecode the iv
     */
    const iv = base64UrlDecode(ivEncoded)
    if (!iv) {
      return null
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    for (const { key } of this.cryptoKeys) {
      const isValidHmac = new Hmac(key).compare(
        `${cipherEncoded}${this.separator}${ivEncoded}`,
        macEncoded
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
        const plainTextBuffer = Buffer.concat([decipher.update(cipherText), decipher.final()])
        return new MessageBuilder().verify(plainTextBuffer, purpose)
      } catch {}
    }

    return null
  }
}
