/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createHmac } from 'node:crypto'
import { safeEqual } from './safe_equal.js'
import { base64UrlEncode } from './base64.js'

/**
 * A generic class for generating SHA-256 Hmac for verifying the value
 * integrity.
 */
export class Hmac {
  #key: Buffer

  constructor(key: Buffer) {
    this.#key = key
  }

  /**
   * Generate the hmac
   */
  generate(value: string) {
    return base64UrlEncode(createHmac('sha256', this.#key).update(value).digest())
  }

  /**
   * Compare raw value against an existing hmac
   */
  compare(value: string, existingHmac: string) {
    return safeEqual(this.generate(value), existingHmac)
  }
}
