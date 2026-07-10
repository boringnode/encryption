/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
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
  #encryptionKey: Buffer

  static readonly #VERSION_PREFIX = 'v1:'
  static readonly #IV_LENGTH = 12
  static readonly #AUTH_TAG_LENGTH = 16

  constructor(config: ChaCha20Poly1305Config) {
    super(config)

    this.#config = config

    if (typeof config.id !== 'string') {
      throw new errors.E_MISSING_ENCRYPTER_ID()
    }

    // Versioned ciphertexts use an algorithm and id-specific key. Unprefixed values
    // continue to use the legacy key during decryption for data migration.
    const encryptionKey = hkdfSync(
      'sha256',
      this.cryptoKey,
      Buffer.alloc(0),
      Buffer.from(`chacha20-poly1305:v1:${config.id}`),
      32
    )
    this.#encryptionKey = Buffer.isBuffer(encryptionKey) ? encryptionKey : Buffer.from(encryptionKey)
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
    const iv = randomBytes(ChaCha20Poly1305.#IV_LENGTH)

    /**
     * Creating cipher
     */
    const cipher = createCipheriv('chacha20-poly1305', this.#encryptionKey, iv, {
      authTagLength: ChaCha20Poly1305.#AUTH_TAG_LENGTH,
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
      `${ChaCha20Poly1305.#VERSION_PREFIX}${base64UrlEncode(cipherText)}`,
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
    const parts = value.split(this.separator)
    if (parts.length !== 4) {
      return null
    }

    const [id, cipherEncoded, ivEncoded, tagEncoded] = parts
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
    const isCurrentVersion = cipherEncoded.startsWith(ChaCha20Poly1305.#VERSION_PREFIX)
    const encodedCipherText = isCurrentVersion
      ? cipherEncoded.slice(ChaCha20Poly1305.#VERSION_PREFIX.length)
      : cipherEncoded
    const cipherText = base64UrlDecode(encodedCipherText)
    if (!cipherText) {
      return null
    }

    /**
     * Make sure we are able to decode the iv
     */
    const iv = base64UrlDecode(ivEncoded)
    if (!iv || iv.length !== ChaCha20Poly1305.#IV_LENGTH) {
      return null
    }

    /**
     * Make sure we are able to decode the tag
     */
    const tag = base64UrlDecode(tagEncoded)
    if (!tag || tag.length !== ChaCha20Poly1305.#AUTH_TAG_LENGTH) {
      return null
    }

    /**
     * The Decipher can raise exceptions with malformed input, so we wrap it
     * to avoid leaking sensitive information
     */
    try {
      const decipher = createDecipheriv(
        'chacha20-poly1305',
        isCurrentVersion ? this.#encryptionKey : this.cryptoKey,
        iv,
        {
          authTagLength: ChaCha20Poly1305.#AUTH_TAG_LENGTH,
        }
      )

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
