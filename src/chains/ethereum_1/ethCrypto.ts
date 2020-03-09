/* eslint-disable @typescript-eslint/no-unused-vars */
import { bufferToHex, ecsign, ecrecover, publicToAddress } from 'ethereumjs-util'
import Wallet from 'ethereumjs-wallet'
import { toBuffer, notImplemented } from '../../helpers'
import { throwNewError } from '../../errors'
import { EthereumAddress, EthereumPublicKey, EthereumSignature, EthereumPrivateKey } from './models/cryptoModels'
import { toEthBuffer } from './helpers/generalHelpers'
import { isEncryptedDataString, encrypt, toEncryptedDataString } from '../../crypto'
// eslint-disable-next-line import/no-cycle
import { toEthereumPublicKey, toEthereumSignature } from './helpers/cryptoModelHelpers'

export function sign(data: string | Buffer, privateKey: string): EthereumSignature {
  const dataBuffer = toEthBuffer(data)
  const keyBuffer = toBuffer(privateKey, 'hex')
  return toEthereumSignature(ecsign(dataBuffer, keyBuffer))
}

export function getEthereumPublicKeyFromSignature(
  signature: EthereumSignature,
  data: string | Buffer,
  encoding: string,
): EthereumPublicKey {
  const { v, r, s } = signature
  return toEthereumPublicKey(ecrecover(toEthBuffer(data), v, r, s).toString())
}

export function getEthereumAddressFromPublicKey(publicKey: EthereumPublicKey): EthereumAddress {
  return bufferToHex(publicToAddress(toEthBuffer(publicKey)))
}

/** Replaces unencrypted privateKey in keys object
 *  Encrypts key using password and salt */
export function encryptAccountPrivateKeysIfNeeded(keys: any, password: string, salt: string) {
  const { privateKey, publicKey } = keys
  const encryptedKeys = {
    privateKey: isEncryptedDataString(privateKey) ? privateKey : encrypt(privateKey, password, salt).toString(),
    publicKey,
  }
  return encryptedKeys
}

export function generateNewAccountKeysAndEncryptPrivateKeys(password: string, salt: string, overrideKeys: any): any {
  const wallet = Wallet.generate()
  const privateKey: EthereumPrivateKey = wallet.getPrivateKeyString()
  const publicKey: EthereumPublicKey = wallet.getPublicKeyString()
  const keys = { privateKey, publicKey }
  const encryptedKeys = encryptAccountPrivateKeysIfNeeded(keys, password, salt)
  return encryptedKeys
}

// TODO: unless the data is signature, not sure what is the purpose of the function.  And how is it possibel to verify that the signature has what public key if the original data is not known
export function verifySignedWithPublicKey(
  publicKey: string | Buffer,
  data: string | Buffer,
  encoding: string,
): boolean {
  notImplemented()
  return null
}
