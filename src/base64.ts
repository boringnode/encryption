/*
 * @boringnode/encryption
 *
 * @license MIT
 * @copyright Boring Node
 */

export function base64UrlEncode(data: Uint8Array | Buffer | string): string {
  const buffer = Buffer.from(data)

  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlDecode(encoded: string): Buffer
export function base64UrlDecode(encoded: string, encoding: BufferEncoding): string
export function base64UrlDecode(
  encoded: string,
  encoding?: BufferEncoding
): Buffer | string | null {
  const padded = encoded
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(encoded.length / 4) * 4, '=')

  try {
    const buffer = Buffer.from(padded, 'base64')
    return encoding ? buffer.toString(encoding) : buffer
  } catch {
    return null
  }
}
