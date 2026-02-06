/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createHash, createHmac, hkdfSync } from 'node:crypto'
import { MessageBuilder, type Secret } from '@poppinss/utils'
import * as errors from '../exceptions.ts'
import { base64UrlEncode } from '../base64.ts'
import type { BaseConfig, CypherText, EncryptOptions } from '../types/main.ts'

export abstract class BaseDriver {
  /**
   * The key for encrypting values. It is derived
   * from the user provided secret.
   */
  cryptoKey: Buffer
  #blindIndexKey: Buffer

  /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
  separator = '.'

  protected constructor(config: BaseConfig) {
    const key = this.#validateAndGetSecret(config.key)
    this.#validateId(config.id)
    this.cryptoKey = createHash('sha256').update(key).digest()

    const rawBlindIndexKey = hkdfSync(
      'sha256',
      this.cryptoKey,
      Buffer.alloc(0),
      Buffer.from(`blind-index:${config.id || 'default'}`),
      32
    )
    this.#blindIndexKey = Buffer.isBuffer(rawBlindIndexKey)
      ? rawBlindIndexKey
      : Buffer.from(rawBlindIndexKey)
  }

  /**
   * Validates the app secret and returns it back as a string
   */
  #validateAndGetSecret(secret: string | Secret<string>): string {
    if (!secret) {
      throw new errors.E_MISSING_ENCRYPTER_KEY()
    }

    const revealedSecret = typeof secret === 'string' ? secret : secret.release()
    if (revealedSecret.length < 16) {
      throw new errors.E_INSECURE_ENCRYPTER_KEY()
    }

    return revealedSecret
  }

  /**
   * Validates encrypter id format when provided.
   */
  #validateId(id?: string) {
    if (typeof id !== 'string') {
      return
    }

    if (id.trim().length === 0 || id.includes(this.separator)) {
      throw new errors.E_INVALID_ENCRYPTER_ID()
    }
  }

  protected computeReturns(values: string[]) {
    return values.join(this.separator) as CypherText
  }

  blindIndex(payload: any, purpose: string): string {
    if (typeof purpose !== 'string' || purpose.trim().length === 0) {
      throw new errors.E_BLIND_INDEX_PURPOSE_REQUIRED()
    }

    const rawPayload = new MessageBuilder().build(payload)
    const payloadBuffer = Buffer.isBuffer(rawPayload) ? rawPayload : Buffer.from(rawPayload)
    const indexPayload = Buffer.concat([
      Buffer.from(purpose),
      Buffer.from(this.separator),
      payloadBuffer,
    ])

    return base64UrlEncode(createHmac('sha256', this.#blindIndexKey).update(indexPayload).digest())
  }

  blindIndexes(payload: any, purpose: string): string[] {
    return [this.blindIndex(payload, purpose)]
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
  abstract encrypt(payload: any, options?: EncryptOptions): CypherText
  abstract encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText

  /**
   * Decrypt value and verify it against a purpose
   */
  abstract decrypt<T extends any>(value: string, purpose?: string): T | null
}
