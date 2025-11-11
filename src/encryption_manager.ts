/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { RuntimeException } from '@poppinss/utils/exception'
import debug from './debug.ts'
import type { MessageVerifier } from './message_verifier.ts'
import type { CypherText, EncryptionDriverContract, ManagerDriverFactory } from './types/main.ts'

export class EncryptionManager<KnownEncryptionDriver extends Record<string, ManagerDriverFactory>>
  implements EncryptionDriverContract
{
  /**
   * Encryption manager config with the
   * list of encryption drivers in use.
   */
  readonly #config: {
    default?: keyof KnownEncryptionDriver
    list: KnownEncryptionDriver
  }

  /**
   * Cache of encryption drivers.
   */
  #encryptionDriverCache: Partial<Record<keyof KnownEncryptionDriver, EncryptionDriverContract>> =
    {}

  constructor(config: { default?: keyof KnownEncryptionDriver; list: KnownEncryptionDriver }) {
    this.#config = config

    debug('creating encryption manager. config: %O', this.#config)
  }

  /**
   * Creates an instance of an encryption driver,
   */
  #createDriver<DriverFactory extends ManagerDriverFactory>(
    factory: DriverFactory
  ): ReturnType<DriverFactory> {
    return factory() as ReturnType<DriverFactory>
  }

  /**
   * Use one of the registered encryption drivers to encrypt values.
   *
   * ```ts
   * manager.use() // returns default encrypter
   * manager.use('aes_256_cbc')
   * ```
   */
  use<EncryptionDriver extends keyof KnownEncryptionDriver>(
    encryptionDriver?: EncryptionDriver
  ): EncryptionDriverContract {
    let driverToUse: keyof KnownEncryptionDriver | undefined =
      encryptionDriver || this.#config.default

    if (!driverToUse) {
      throw new RuntimeException(
        'Cannot create encryption instance. No default encryption is defined in the config'
      )
    }

    /**
     * Use cached copy if exists
     */
    const cachedDriver = this.#encryptionDriverCache[driverToUse]
    if (cachedDriver) {
      debug('using encrypter from cache. name: "%s"', driverToUse)
      return cachedDriver
    }

    const driverFactory = this.#config.list[driverToUse]

    /**
     * Create a new instance of Encryption class with the selected
     * driver and cache it
     */
    debug('creating encryption driver. name: "%s"', driverToUse)
    const encryption = this.#createDriver(driverFactory)
    this.#encryptionDriverCache[driverToUse] = encryption

    return encryption
  }

  getMessageVerifier(): MessageVerifier {
    return this.use().getMessageVerifier()
  }

  encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText {
    return this.use().encrypt(payload, expiresIn, purpose)
  }

  decrypt<T extends any>(value: string, purpose?: string): T | null {
    return this.use().decrypt(value, purpose)
  }
}
