/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { RuntimeException } from '@poppinss/utils/exception'
import debug from './debug.ts'
import { Encryption } from './encryption.ts'
import type { MessageVerifier } from './message_verifier.ts'
import type { CypherText, EncryptionConfig, EncryptOptions } from './types/main.ts'

export class EncryptionManager<KnownEncrypters extends Record<string, EncryptionConfig>> {
  /**
   * Encryption manager config with the
   * list of encrypters in use.
   */
  readonly #config: {
    default?: keyof KnownEncrypters
    list: KnownEncrypters
  }

  /**
   * Cache of encryption instances.
   */
  #encryptionCache: Partial<Record<keyof KnownEncrypters, Encryption>> = {}

  constructor(config: { default?: keyof KnownEncrypters; list: KnownEncrypters }) {
    this.#config = config

    debug('creating encryption manager. config: %O', this.#config)
  }

  /**
   * Use one of the registered encrypters to encrypt values.
   *
   * ```ts
   * manager.use() // returns default encrypter
   * manager.use('aes_256_cbc')
   * ```
   */
  use<EncrypterName extends keyof KnownEncrypters>(encrypterName?: EncrypterName): Encryption {
    let encrypterToUse: keyof KnownEncrypters | undefined = encrypterName || this.#config.default

    if (!encrypterToUse) {
      throw new RuntimeException(
        'Cannot create encryption instance. No default encryption is defined in the config'
      )
    }

    /**
     * Use cached copy if exists
     */
    const cachedEncryption = this.#encryptionCache[encrypterToUse]
    if (cachedEncryption) {
      debug('using encrypter from cache. name: "%s"', encrypterToUse)
      return cachedEncryption
    }

    const encrypterConfig = this.#config.list[encrypterToUse]

    /**
     * Create a new instance of Encryption class with the selected
     * config and cache it
     */
    debug('creating encryption instance. name: "%s"', encrypterToUse)
    const encryption = new Encryption(encrypterConfig)
    this.#encryptionCache[encrypterToUse] = encryption

    return encryption
  }

  getMessageVerifier(): MessageVerifier {
    return this.use().getMessageVerifier()
  }

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

    return this.use().encrypt(payload, expiresIn, actualPurpose)
  }

  decrypt<T extends any>(value: string, purpose?: string): T | null {
    return this.use().decrypt(value, purpose)
  }
}
