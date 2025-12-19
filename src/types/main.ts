/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { type Secret } from '@poppinss/utils'

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
  key: string | Secret<string>
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

/**
 * Configuration for the Encryption class
 */
export interface EncryptionConfig {
  /**
   * Factory function that creates a driver instance for a given key
   */
  driver: (key: string | Secret<string>) => EncryptionDriverContract

  /**
   * List of keys to use for encryption/decryption.
   * The first key is used for encryption, all keys are tried for decryption.
   */
  keys: (string | Secret<string>)[]
}
