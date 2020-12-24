import sjcl, { SjclCipherEncryptParams } from '@aikon/sjcl'
import { EncryptedDataString, EncryptionMode, EncryptionOptions } from './symmetricModels'
import { ensureEncryptedValueIsObject } from './cryptoHelpers'
import { isAString } from '../helpers'

export * from './symmetricModels'

export const defaultIter = 1000000
export const defaultMode = EncryptionMode.Gcm

/** Verifies that the value is a valid, stringified JSON Encrypted object */
export function isEncryptedDataString(value: string): value is EncryptedDataString {
  if (!isAString(value)) return false
  // this is an oversimplified check just to prevent assigning a wrong string
  return value.match(/^\{.+iv.+iter.+ks.+ts.+mode.+adata.+cipher.+ct.+\}$/is) !== null
}

/** Ensures that the value comforms to a well-formed, stringified JSON Encrypted Object */
export function toEncryptedDataString(value: any): EncryptedDataString {
  if (isEncryptedDataString(value)) {
    return value
  }
  throw new Error(`Not valid encrypted data string:${value}`)
}

// decrypt and encrypt

// NOTE Passing in at least an empty string for the salt, will prevent cached keys, which can lead to false positives in the test suite
/** Derive the key used for encryption/decryption */
export function deriveKey(password: string, iter: number, salt: string = ''): sjcl.BitArray {
  const { key } = sjcl.misc.cachedPbkdf2(password, { iter, salt })
  return key
}

/** Decrypts the encrypted value with the derived key */
export function decryptWithKey(encrypted: EncryptedDataString | any, derivedKey: sjcl.BitArray): string {
  const encryptedAsObject = ensureEncryptedValueIsObject(encrypted)
  const encryptedDataString = JSON.stringify(encryptedAsObject)
  return sjcl.decrypt(derivedKey, encryptedDataString)
}

/** Decrypts the encrypted value using a password, and salt (and optional iter value)
 * Uses AES algorithm and SHA256 hash function
 * The encrypted value is either a stringified JSON object or a JSON object */
export function decryptWithPassword(
  encrypted: EncryptedDataString | any,
  password: string,
  options?: EncryptionOptions,
): string {
  const { salt } = options || {}
  const parsedObject = ensureEncryptedValueIsObject(encrypted)

  // get iter from encrypted string (can be overridden by options)
  const iter = options?.iter || parsedObject?.iter

  return decryptWithKey(encrypted, deriveKey(password, iter, salt))
}

/** Encrypts the private key with the derived key  */
export function encryptWithKey(
  unencrypted: string,
  cryptoParams: SjclCipherEncryptParams,
  derivedKey: sjcl.BitArray,
): sjcl.SjclCipherEncrypted {
  const params = { ...cryptoParams } as sjcl.SjclCipherEncryptParams
  const encrypted = ensureEncryptedValueIsObject(sjcl.encrypt(derivedKey, unencrypted, params) as any)
  return encrypted
}

/** Encrypts a string using a password and optional salt */
export function encryptWithPassword(
  unencrypted: string,
  password: string,
  options?: EncryptionOptions,
): EncryptedDataString {
  const { iter = defaultIter, mode = defaultMode, salt } = options || {}
  const cryptoParams = { mode, iter } as SjclCipherEncryptParams
  return toEncryptedDataString(
    JSON.stringify(encryptWithKey(unencrypted, cryptoParams, deriveKey(password, iter, salt))),
  )
}
