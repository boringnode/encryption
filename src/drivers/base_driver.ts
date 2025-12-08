/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createHash } from 'node:crypto'
import * as errors from '../exceptions.ts'
import type { BaseConfig, CypherText } from '../types/main.ts'

export abstract class BaseDriver {
  /**
   * The key for encrypting values. It is derived
   * from the user provided secret.
   */
  cryptoKey: Buffer

  /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
  separator = '.'

  protected constructor(config: BaseConfig) {
    this.#validateSecret(config.key)
    this.cryptoKey = createHash('sha256').update(config.key).digest()
  }

  /**
   * Validates the app secret
   */
  #validateSecret(secret: string) {
    if (!secret) {
      throw new errors.E_MISSING_ENCRYPTER_KEY()
    }

    if (secret.length < 16) {
      throw new errors.E_INSECURE_ENCRYPTER_KEY()
    }
  }

  protected computeReturns(values: string[]) {
    return values.join(this.separator) as CypherText
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
  abstract encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText

  /**
   * Decrypt value and verify it against a purpose
   */
  abstract decrypt<T extends any>(value: string, purpose?: string): T | null
}
