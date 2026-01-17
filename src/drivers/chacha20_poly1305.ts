/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { MessageBuilder, type Secret } from '@poppinss/utils'
import { BaseDriver } from './base_driver.ts'
import * as errors from '../exceptions.ts'
import type {
  ChaCha20Poly1305Config,
  CypherText,
  EncryptionConfig,
  EncryptionDriverContract,
  EncryptOptions,
} from '../types/main.ts'
import { base64UrlDecode, base64UrlEncode } from '../base64.ts'

export interface ChaCha20Poly1305DriverConfig {
  id: string
  keys: (string | Secret<string>)[]
}

export function chacha20poly1305(config: ChaCha20Poly1305DriverConfig) {
  return {
    driver: (key) => new ChaCha20Poly1305({ id: config.id, key }),
    keys: config.keys,
  } satisfies EncryptionConfig
}

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
  encrypt(payload: any, options?: EncryptOptions): CypherText
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText
  encrypt(
    payload: any,
    expiresInOrOptions?: string | number | EncryptOptions,
    purpose?: string
  ): CypherText {
    let expiresIn: string | number | undefined
    let actualPurpose: string | undefined

    if (typeof expiresInOrOptions === 'object' && expiresInOrOptions !== null) {
      expiresIn = expiresInOrOptions.expiresIn
      actualPurpose = expiresInOrOptions.purpose
    } else {
      expiresIn = expiresInOrOptions
      actualPurpose = purpose
    }

    /**
     * Using a random string as the iv for generating unpredictable values
     */
    const iv = randomBytes(12)

    /**
     * Creating cipher
     */
    const cipher = createCipheriv('chacha20-poly1305', this.cryptoKey, iv, {
      authTagLength: 16,
    })

    if (actualPurpose) {
      cipher.setAAD(Buffer.from(actualPurpose), {
        plaintextLength: Buffer.byteLength(actualPurpose),
      })
    }

    /**
     * Encoding value to a string so that we can set it on the cipher
     */
    const plainText = new MessageBuilder().build(payload, expiresIn)

    /**
     * Set final to the cipher instance and encrypt it
     */
    const cipherText = Buffer.concat([cipher.update(plainText), cipher.final()])

    const tag = cipher.getAuthTag()

    return this.computeReturns([
      this.#config.id,
      base64UrlEncode(cipherText),
      base64UrlEncode(iv),
      base64UrlEncode(tag),
    ])
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
     * i.e.: [id].[encrypted value].[iv].[tag]
     */
    const [id, cipherEncoded, ivEncoded, tagEncoded] = value.split(this.separator)
    if (!id || !cipherEncoded || !ivEncoded || !tagEncoded) {
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
     * Make sure we are able to decode the tag
     */
    const tag = base64UrlDecode(tagEncoded)
    if (!tag) {
      return null
    }

    /**
     * The Decipher can raise exceptions with malformed input, so we wrap it
     * to avoid leaking sensitive information
     */
    try {
      const decipher = createDecipheriv('chacha20-poly1305', this.cryptoKey, iv, {
        authTagLength: 16,
      })

      if (purpose) {
        decipher.setAAD(Buffer.from(purpose), { plaintextLength: Buffer.byteLength(purpose) })
      }

      decipher.setAuthTag(tag)

      const plain = Buffer.concat([decipher.update(cipherText), decipher.final()])
      return new MessageBuilder().verify(plain)
    } catch {
      return null
    }
  }
}
