/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createHash } from 'node:crypto'
import * as errors from '../exceptions.js'
import { MessageVerifier } from '../message_verifier.js'
import type { BaseConfig, CypherText } from '../types/main.js'

export abstract class BaseDriver {
  /**
   * The key for signing and encrypting values. It is derived
   * from the user provided secret.
   */
  cryptoKeys = new Set<{ key: Buffer; verifier: MessageVerifier }>()

  /**
   * Use `dot` as a separator for joining encrypted value, iv and the
   * hmac hash. The idea is borrowed from JWTs.
   */
  separator = '.'

  protected constructor(config: BaseConfig) {
    if (!config.keys || !Array.isArray(config.keys)) {
      throw new errors.E_MISSING_ENCRYPTER_KEY()
    }

    for (const key of config.keys) {
      this.#validateSecret(key)

      const cryptoKey = createHash('sha256').update(key).digest()
      this.cryptoKeys.add({ key: cryptoKey, verifier: new MessageVerifier(key) })
    }
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

  computeReturns(values: string[]) {
    return values.join(this.separator) as CypherText
  }

  getFirstKey() {
    const [firstKey] = this.cryptoKeys
    return firstKey
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
