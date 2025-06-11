/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

export type CypherText = `${string}.${string}.${string}.${string}`

/**
 * The contract Encryption drivers should adhere to
 */
export interface EncryptionDriverContract {
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
  encrypt(payload: any, expiresIn?: string | number, purpose?: string): CypherText

  /**
   * Decrypt value and verify it against a purpose
   */
  decrypt<T extends any>(value: string, purpose?: string): T | null
}

/**
 * Factory function to return the driver implementation. The method
 * cannot be async because the API that calls this method is not
 * async in the first place.
 */
export type ManagerDriverFactory = () => EncryptionDriverContract

export interface BaseConfig {
  keys: string[]
}

export interface LegacyConfig extends BaseConfig {}
export interface AES256CBCConfig extends BaseConfig {
  id: string
}
export interface AES256GCMConfig extends BaseConfig {
  id: string
}
export interface ChaCha20Poly1305Config extends BaseConfig {
  id: string
}

export type Config<KnownEncrypters extends Record<string, ManagerDriverFactory>> = {
  default?: keyof KnownEncrypters
  list: KnownEncrypters
}
