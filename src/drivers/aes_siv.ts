/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

import { createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto'
import { MessageBuilder, type Secret } from '@poppinss/utils'
import { BaseDriver } from './base_driver.ts'
import { base64UrlDecode, base64UrlEncode } from '../base64.ts'
import * as errors from '../exceptions.ts'
import { safeEqual } from '../safe_equal.ts'
import type {
  AESSIVConfig,
  CypherText,
  EncryptionConfig,
  EncryptionDriverContract,
  EncryptOptions,
} from '../types/main.ts'

export interface AESSIVDriverConfig {
  id: string
  key: string | Secret<string>
}

export function aessiv(config: AESSIVDriverConfig) {
  return {
    driver: (key) => new AESSIV({ id: config.id, key }),
    keys: [config.key],
  } satisfies EncryptionConfig
}

export class AESSIV extends BaseDriver implements EncryptionDriverContract {
  #config: AESSIVConfig
  static readonly #BLOCK_SIZE = 16
  static readonly #ZERO_BLOCK = Buffer.alloc(AESSIV.#BLOCK_SIZE, 0)

  constructor(config: AESSIVConfig) {
    super(config)

    this.#config = config

    if (typeof config.id !== 'string') {
      throw new errors.E_MISSING_ENCRYPTER_ID()
    }
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

    if (expiresIn !== undefined) {
      throw new errors.E_DETERMINISTIC_DRIVER_EXPIRES_IN_NOT_SUPPORTED()
    }

    const { macKey, encryptionKey } = this.#deriveKeys()
    const plainTextValue = new MessageBuilder().build(payload)
    const plainText = Buffer.isBuffer(plainTextValue) ? plainTextValue : Buffer.from(plainTextValue)
    const associatedData = actualPurpose ? [Buffer.from(actualPurpose)] : []

    const { syntheticIv, cipherText } = AESSIV.encryptRaw(
      macKey,
      encryptionKey,
      plainText,
      associatedData
    )

    return this.computeReturns([
      this.#config.id,
      base64UrlEncode(cipherText),
      base64UrlEncode(syntheticIv),
    ])
  }

  decrypt<T extends any>(value: string, purpose?: string): T | null {
    if (typeof value !== 'string') {
      return null
    }

    const parts = value.split(this.separator)
    if (parts.length !== 3) {
      return null
    }

    const [id, cipherEncoded, syntheticIvEncoded] = parts
    if (!id || !cipherEncoded || !syntheticIvEncoded) {
      return null
    }

    if (id !== this.#config.id) {
      return null
    }

    const cipherText = base64UrlDecode(cipherEncoded)
    if (!cipherText) {
      return null
    }

    const syntheticIv = base64UrlDecode(syntheticIvEncoded)
    if (!syntheticIv || syntheticIv.length !== AESSIV.#BLOCK_SIZE) {
      return null
    }

    try {
      const { macKey, encryptionKey } = this.#deriveKeys()
      const associatedData = purpose ? [Buffer.from(purpose)] : []
      const plainText = AESSIV.decryptRaw(
        macKey,
        encryptionKey,
        syntheticIv,
        cipherText,
        associatedData
      )
      if (!plainText) return null

      return new MessageBuilder().verify(plainText)
    } catch {
      return null
    }
  }

  #deriveKeys() {
    const rawDerivedKey = hkdfSync(
      'sha256',
      this.cryptoKey,
      Buffer.alloc(0),
      Buffer.from(`aes-siv:${this.#config.id}`),
      64
    )

    const derivedKey = Buffer.isBuffer(rawDerivedKey) ? rawDerivedKey : Buffer.from(rawDerivedKey)

    return {
      macKey: derivedKey.subarray(0, 32),
      encryptionKey: derivedKey.subarray(32),
    }
  }

  /**
   * Low-level AES-SIV primitive. Exposed as static for RFC 5297 conformance tests.
   */
  static encryptRaw(
    macKey: Buffer,
    encryptionKey: Buffer,
    plainText: Buffer,
    associatedData: Buffer[] = []
  ): {
    syntheticIv: Buffer
    cipherText: Buffer
  } {
    AESSIV.#ensureSupportedKeyLength(macKey, encryptionKey)

    const syntheticIv = AESSIV.#s2v(macKey, associatedData, plainText)
    const iv = AESSIV.#toCtrIv(syntheticIv)
    const cipher = createCipheriv(AESSIV.#getCtrAlgorithm(encryptionKey), encryptionKey, iv)
    const cipherText = Buffer.concat([cipher.update(plainText), cipher.final()])

    return { syntheticIv, cipherText }
  }

  static decryptRaw(
    macKey: Buffer,
    encryptionKey: Buffer,
    syntheticIv: Buffer,
    cipherText: Buffer,
    associatedData: Buffer[] = []
  ): Buffer | null {
    AESSIV.#ensureSupportedKeyLength(macKey, encryptionKey)

    const iv = AESSIV.#toCtrIv(syntheticIv)
    const decipher = createDecipheriv(AESSIV.#getCtrAlgorithm(encryptionKey), encryptionKey, iv)
    const plainText = Buffer.concat([decipher.update(cipherText), decipher.final()])
    const expectedSyntheticIv = AESSIV.#s2v(macKey, associatedData, plainText)

    if (!safeEqual(expectedSyntheticIv, syntheticIv)) {
      return null
    }

    return plainText
  }
  static #toCtrIv(syntheticIv: Buffer): Buffer {
    const iv = Buffer.from(syntheticIv)
    iv[8] &= 0x7f
    iv[12] &= 0x7f
    return iv
  }

  static #s2v(macKey: Buffer, associatedData: Buffer[], plainText: Buffer): Buffer {
    let d = AESSIV.#cmac(macKey, AESSIV.#ZERO_BLOCK)

    for (const item of associatedData) {
      d = AESSIV.#xorBuffers(AESSIV.#dbl(d), AESSIV.#cmac(macKey, item))
    }

    const t =
      plainText.length >= AESSIV.#BLOCK_SIZE
        ? AESSIV.#xorEnd(plainText, d)
        : AESSIV.#xorBuffers(AESSIV.#dbl(d), AESSIV.#pad(plainText))

    return AESSIV.#cmac(macKey, t)
  }

  static #cmac(key: Buffer, message: Buffer): Buffer {
    const l = AESSIV.#aesEcbEncryptBlock(key, AESSIV.#ZERO_BLOCK)
    const k1 = AESSIV.#dbl(l)
    const k2 = AESSIV.#dbl(k1)

    let blockCount = Math.ceil(message.length / AESSIV.#BLOCK_SIZE)
    blockCount = blockCount === 0 ? 1 : blockCount

    const isLastBlockComplete = message.length !== 0 && message.length % AESSIV.#BLOCK_SIZE === 0
    let lastBlock: Buffer
    if (isLastBlockComplete) {
      const lastStart = (blockCount - 1) * AESSIV.#BLOCK_SIZE
      lastBlock = AESSIV.#xorBuffers(
        message.subarray(lastStart, lastStart + AESSIV.#BLOCK_SIZE),
        k1
      )
    } else {
      const lastStart = (blockCount - 1) * AESSIV.#BLOCK_SIZE
      lastBlock = AESSIV.#xorBuffers(AESSIV.#pad(message.subarray(lastStart)), k2)
    }

    let x: Buffer<ArrayBufferLike> = Buffer.alloc(AESSIV.#BLOCK_SIZE, 0)
    for (let index = 0; index < blockCount - 1; index++) {
      const start = index * AESSIV.#BLOCK_SIZE
      const block = message.subarray(start, start + AESSIV.#BLOCK_SIZE)
      x = AESSIV.#aesEcbEncryptBlock(key, AESSIV.#xorBuffers(x, block))
    }

    return AESSIV.#aesEcbEncryptBlock(key, AESSIV.#xorBuffers(x, lastBlock))
  }

  static #aesEcbEncryptBlock(key: Buffer, block: Buffer): Buffer {
    const cipher = createCipheriv(AESSIV.#getEcbAlgorithm(key), key, null)
    cipher.setAutoPadding(false)
    return Buffer.concat([cipher.update(block), cipher.final()])
  }

  static #dbl(block: Buffer): Buffer {
    const output = Buffer.alloc(AESSIV.#BLOCK_SIZE)
    const msbSet = (block[0] & 0x80) !== 0

    let carry = 0
    for (let index = AESSIV.#BLOCK_SIZE - 1; index >= 0; index--) {
      const value = block[index]
      output[index] = ((value << 1) & 0xff) | carry
      carry = (value & 0x80) !== 0 ? 1 : 0
    }

    if (msbSet) {
      output[AESSIV.#BLOCK_SIZE - 1] ^= 0x87
    }

    return output
  }

  static #xorBuffers(left: Buffer, right: Buffer): Buffer {
    const output = Buffer.alloc(left.length)
    for (const [index, value] of left.entries()) {
      output[index] = value ^ right[index]
    }
    return output
  }

  static #xorEnd(buffer: Buffer, block: Buffer): Buffer {
    const output = Buffer.from(buffer)
    const offset = output.length - AESSIV.#BLOCK_SIZE
    for (let index = 0; index < AESSIV.#BLOCK_SIZE; index++) {
      output[offset + index] ^= block[index]
    }
    return output
  }

  static #pad(buffer: Buffer): Buffer {
    const output = Buffer.alloc(AESSIV.#BLOCK_SIZE, 0)
    buffer.copy(output)
    output[buffer.length] = 0x80
    return output
  }

  static #getEcbAlgorithm(key: Buffer): 'aes-128-ecb' | 'aes-192-ecb' | 'aes-256-ecb' {
    switch (key.length) {
      case 16: {
        return 'aes-128-ecb'
      }
      case 24: {
        return 'aes-192-ecb'
      }
      case 32: {
        return 'aes-256-ecb'
      }
      default: {
        throw new TypeError('Invalid AES key length for SIV')
      }
    }
  }

  static #getCtrAlgorithm(key: Buffer): 'aes-128-ctr' | 'aes-192-ctr' | 'aes-256-ctr' {
    switch (key.length) {
      case 16: {
        return 'aes-128-ctr'
      }
      case 24: {
        return 'aes-192-ctr'
      }
      case 32: {
        return 'aes-256-ctr'
      }
      default: {
        throw new TypeError('Invalid AES key length for SIV')
      }
    }
  }

  static #ensureSupportedKeyLength(macKey: Buffer, encryptionKey: Buffer) {
    if (macKey.length !== encryptionKey.length) {
      throw new TypeError('SIV subkeys must have the same length')
    }

    AESSIV.#getEcbAlgorithm(macKey)
    AESSIV.#getCtrAlgorithm(encryptionKey)
  }
}
