/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { MessageVerifier } from './message_verifier.ts'
import type { CypherText, EncryptionConfig, EncryptionDriverContract } from './types/main.ts'

/**
 * Encryption class that wraps a driver and manages multiple keys.
 * Encrypts with the first key, decrypts by trying all keys.
 */
export class Encryption {
  #drivers: EncryptionDriverContract[]
  #verifier: MessageVerifier

  constructor(config: EncryptionConfig) {
    this.#drivers = config.keys.map((key) => config.driver(key))
    this.#verifier = new MessageVerifier(config.keys)
  }

  /**
   * Encrypt a value using the first key
   */
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText {
    return this.#drivers[0].encrypt(payload, expiresIn, purpose)
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

  /**
   * Get the message verifier instance
   */
  getMessageVerifier(): MessageVerifier {
    return this.#verifier
  }
}
