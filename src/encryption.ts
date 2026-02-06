/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { MessageVerifier } from './message_verifier.ts'
import * as errors from './exceptions.ts'
import type {
  CypherText,
  EncryptionConfig,
  EncryptionDriverContract,
  EncryptOptions,
} from './types/main.ts'

/**
 * Encryption class that wraps a driver and manages multiple keys.
 * Encrypts with the first key, decrypts by trying all keys.
 */
export class Encryption {
  #drivers: EncryptionDriverContract[]
  #verifier: MessageVerifier

  constructor(config: EncryptionConfig) {
    if (config.keys.length === 0) {
      throw new errors.E_MISSING_ENCRYPTER_KEYS()
    }

    this.#drivers = config.keys.map((key) => config.driver(key))
    this.#verifier = new MessageVerifier(config.keys)
  }

  /**
   * Encrypt a value using the first key
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

    return this.#drivers[0].encrypt(payload, expiresIn, actualPurpose)
  }

  /**
   * Decrypt a value by trying all keys
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null {
    for (const driver of this.#drivers) {
      const result = driver.decrypt<T>(value, purpose)
      if (result !== null) {
        return result
      }
    }
    return null
  }

  blindIndex(payload: any, purpose: string): string {
    return this.#drivers[0].blindIndex(payload, purpose)
  }

  blindIndexes(payload: any, purpose: string): string[] {
    const indexes = new Set<string>()

    for (const driver of this.#drivers) {
      for (const index of driver.blindIndexes(payload, purpose)) {
        indexes.add(index)
      }
    }

    return [...indexes]
  }

  /**
   * Get the message verifier instance
   */
  getMessageVerifier(): MessageVerifier {
    return this.#verifier
  }
}
