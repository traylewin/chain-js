import * as algosdk from 'algosdk'
import { byteArrayToHexString, hexStringToByteArray } from '../../helpers'
import { EncryptedDataString } from '../../models'
import {
  AlgorandGeneratedAccountStruct,
  AlgorandKeyPair,
  AlgorandPrivateKey,
  AlgorandPublicKey,
  AlgorandSignature,
} from './models'
import * as ed25519Crypto from '../../crypto/ed25519Crypto'
import { calculatePasswordByteArray, toAlgorandPrivateKey, toAlgorandPublicKey, toAlgorandSignature } from './helpers'

/** Verifies that the value is a valid encrypted string */
export function isEncryptedDataString(value: string): value is EncryptedDataString {
  return ed25519Crypto.isEncryptedDataString(value)
}

/** Ensures that the value confirms to a well-formed and encrypted string */
export function toEncryptedDataString(value: any): EncryptedDataString {
  return ed25519Crypto.toEncryptedDataString(value)
}

/** Encrypts a string using a password and a nonce
 *  Nacl requires password to be in a 32 byte array format. Hence we derive a key from the password string using the provided salt
 */
export function encrypt(unencrypted: string, password: string, salt: string): EncryptedDataString {
  const passwordKey = calculatePasswordByteArray(password, salt)
  const encrypted = ed25519Crypto.encrypt(unencrypted, passwordKey)
  return byteArrayToHexString(encrypted) as EncryptedDataString
}

/** Decrypts the encrypted value using nacl
 * Nacl requires password to be in a 32 byte array format
 */
export function decrypt(encrypted: EncryptedDataString | any, password: string, salt: string): string {
  const passwordKey = calculatePasswordByteArray(password, salt)
  const decrypted = ed25519Crypto.decrypt(encrypted, passwordKey)
  return byteArrayToHexString(decrypted)
}

/** Signs a string with a private key */
export function sign(data: string, privateKey: AlgorandPrivateKey | string): AlgorandSignature {
  const signature = ed25519Crypto.sign(hexStringToByteArray(data), hexStringToByteArray(privateKey))
  return toAlgorandSignature(byteArrayToHexString(signature))
}

/** Verify that the signed data was signed using the given key (signed with the private key for the provided public key) */
export function verifySignedWithPublicKey(
  data: string,
  publicKey: AlgorandPublicKey,
  signature: AlgorandSignature,
): boolean {
  return ed25519Crypto.verify(
    hexStringToByteArray(data),
    hexStringToByteArray(publicKey),
    hexStringToByteArray(signature),
  )
}

/** Replaces unencrypted privateKey in keys object
 *  Encrypts key using password */
function encryptAccountPrivateKeysIfNeeded(keys: AlgorandKeyPair, password: string, salt: string) {
  const { privateKey, publicKey } = keys
  const encryptedKeys = {
    privateKey: encrypt(privateKey, password, salt),
    publicKey,
  }
  return encryptedKeys as AlgorandKeyPair
}

/** Gets the algorand public key from the given private key in the account
 * Returns hex public key and private key
 */
export function getAlgorandKeyPairFromAccount(account: AlgorandGeneratedAccountStruct): AlgorandKeyPair {
  const { sk: privateKey } = account
  const { publicKey, secretKey } = ed25519Crypto.getKeyPairFromPrivateKey(privateKey)
  return {
    publicKey: toAlgorandPublicKey(byteArrayToHexString(publicKey)),
    privateKey: toAlgorandPrivateKey(byteArrayToHexString(secretKey)),
  }
}

/** Generates new public and private key pair
 * Encrypts the private key using password
 */
export function generateNewAccountKeysAndEncryptPrivateKeys(password: string, salt: string) {
  const newAccount = algosdk.generateAccount()
  const keys = getAlgorandKeyPairFromAccount(newAccount)
  const encryptedKeys = encryptAccountPrivateKeysIfNeeded(keys, password, salt)
  return encryptedKeys
}
