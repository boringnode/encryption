/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { MessageBuilder } from '@poppinss/utils'
import { BaseDriver } from './base_driver.js'
import { Hmac } from '../hmac.js'
import * as errors from '../exceptions.js'
import type { ChaCha20Poly1305Config, EncryptionDriverContract } from '../types/main.js'

export class ChaCha20Poly1305 extends BaseDriver implements EncryptionDriverContract {
  #config: ChaCha20Poly1305Config

  constructor(config: ChaCha20Poly1305Config) {
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): string {
    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = randomBytes(12)

    /**
     * Creating cipher
     */
    const cipher = createCipheriv('chacha20-poly1305', this.getFirstKey().key, iv, {
      authTagLength: 16,
    })

    if (purpose) {
      cipher.setAAD(Buffer.from(purpose), { plaintextLength: Buffer.byteLength(purpose) })
    }

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const encodedValue = new MessageBuilder().build(payload, expiresIn)

    /**
     * Set final to the cipher instance and encrypt it
     */
    const encrypted = Buffer.concat([cipher.update(encodedValue, 'utf-8'), cipher.final()])

    /**
     * Concatenate `encrypted value` and `iv` by urlEncoding them. The concatenation is required
     * to generate the HMAC, so that HMAC checks for integrity of both the `encrypted value`
     * and the `iv`.
     */
    const result = `${encrypted.toString('hex')}${this.separator}${iv.toString('hex')}`

    const nounce = cipher.getAuthTag().toString('hex')

    /**
     * Returns the id + result + nounce + hmac
     */
    const hmac = new Hmac(this.getFirstKey().key).generate(result)
    return this.computeReturns([this.#config.id, result, nounce, hmac])
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
     * [id].[encrypted value].[iv].[nounce].[hmac]
     */
    const [id, encryptedEncoded, ivEncoded, nounceEncoded, hmac] = value.split(this.separator)
    if (!id || !encryptedEncoded || !ivEncoded || !nounceEncoded || !hmac) {
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
    const encrypted = Buffer.from(encryptedEncoded, 'hex')
    if (!encrypted) {
      return null
    }

    /**
     * Make sure we are able to decode the iv
     */
    const iv = Buffer.from(ivEncoded, 'hex')
    if (!iv) {
      return null
    }

    /**
     * Make sure we are able to decode the nounce
     */
    const nounce = Buffer.from(nounceEncoded, 'hex')
    if (!nounce) {
      return null
    }

    /**
     * Make sure the hash is correct, it means the first 2 parts of the
     * string are not tampered.
     */
    for (const { key } of this.cryptoKeys) {
      const isValidHmac = new Hmac(key).compare(
        `${encryptedEncoded}${this.separator}${ivEncoded}`,
        hmac
      )

      if (!isValidHmac) {
        continue
      }

      /**
       * The Decipher can raise exceptions with malformed input, so we wrap it
       * to avoid leaking sensitive information
       */
      try {
        const decipher = createDecipheriv('chacha20-poly1305', key, iv, {
          authTagLength: 16,
        })

        /**
         * Set the purpose to decipher
         */
        if (purpose) {
          decipher.setAAD(Buffer.from(purpose), { plaintextLength: Buffer.byteLength(purpose) })
        }

        /**
         * Set the nounce
         */
        decipher.setAuthTag(nounce)

        const decrypted = decipher.update(encrypted) + decipher.final('utf8')
        return new MessageBuilder().verify(decrypted)
      } catch {}
    }

    return null
  }
}
