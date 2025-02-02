import {
  BN,
  bufferToHex,
  ECDSASignature,
  fromRpcSig,
  isValidAddress,
  isValidPrivate,
  isValidPublic,
  privateToAddress,
} from 'ethereumjs-util'
import {
  ensureHexPrefix,
  ensureHexPrefixForPublicKey,
  hasHexPrefix,
  isABuffer,
  isAString,
  isHexString,
  isNullOrEmpty,
  jsonParseAndRevive,
  toChainEntityName,
  toHexStringIfNeeded,
  tryParseJSON,
} from '../../../helpers'
import {
  AlternateUnitMap,
  EthereumAddress,
  EthereumPrivateKey,
  EthereumPublicKey,
  EthereumSignature,
  EthereumSignatureNative,
  EthereumTxData,
  EthUnit,
} from '../models'
import { toEthBuffer } from './generalHelpers'

// todo eth - this should not have copied code - is the bug worked-around? if not, we should consider using a diff library
// Reimplemented from ethereumjs-util module to workaround a current bug
/** Checks if a valid signature with ECDSASignature */
export function isValidSignature(v: number, r: Buffer, s: Buffer): boolean {
  if (!v || !r || !s) return false
  const SECP256K1_N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16)
  const SECP256K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

  if (r.length !== 32 || s.length !== 32) {
    return false
  }

  const rBN: BN = new BN(r)
  const sBN: BN = new BN(s)

  if (rBN.isZero() || rBN.gt(SECP256K1_N) || sBN.isZero() || sBN.gt(SECP256K1_N)) {
    return false
  }

  if (sBN.cmp(SECP256K1_N_DIV_2) === 1) {
    return false
  }
  return true
}

export function isValidEthereumTxData(value: string | Buffer | EthereumTxData): value is EthereumTxData {
  if (isNullOrEmpty(value)) return false
  // return false for '0x' as well as empty string
  if (isAString(value)) return ensureHexPrefix(value as string).length > 2
  return true
}

export function isValidEthereumPublicKey(value: string | EthereumPublicKey): value is EthereumPublicKey {
  if (!value) return false
  return isValidPublic(toEthBuffer(ensureHexPrefixForPublicKey(value)))
}

export function isValidEthereumPrivateKey(value: EthereumPrivateKey | string): value is EthereumPrivateKey {
  if (!value) return false
  return isValidPrivate(toEthBuffer(ensureHexPrefix(value)))
}

/** whether a value is a valid native Ethereum signature (or a strinigified version of it) */
export function isValidEthereumSignatureNative(
  value: EthereumSignature | string | ECDSASignature,
): value is EthereumSignature {
  let signature: ECDSASignature
  // this is an oversimplified check just to prevent assigning a wrong string
  // signatures are actually verified in transaction object
  if (!value) return false
  if (typeof value === 'string') {
    signature = jsonParseAndRevive(value)
  } else {
    signature = value
  }
  const { v, r, s } = signature
  return isValidSignature(v, r, s)
}

/** whether a value is a valid native Ethereum signature (or a strinigified version of it) */
export function isValidEthereumSignature(
  value: EthereumSignature | string | ECDSASignature,
): value is EthereumSignature {
  return isValidEthereumSignatureNative(value)
}

/** whether value is an Ethereum address */
export function isValidEthereumAddress(value: string | Buffer | EthereumAddress): boolean {
  if (!value) return false
  if (typeof value === 'string') return isValidAddress(value)
  return true
}

/** whether value is an Ethereum TxId (Hash) */
export function isValidEthereumTxId(value: string | Buffer | EthereumAddress): boolean {
  if (!value || !hasHexPrefix(value)) return false
  const buffer = toEthBuffer(value)
  return buffer.length === 32
}

/** throws error if value is not a valid transactionId */
export function assertIsValidTransactionId(value: any) {
  if (!isValidEthereumTxId(value)) {
    throw new Error(`Not valid ethereum transactionId:${value && JSON.stringify(value)}.`)
  }
}

/** Accepts hex string checks if a valid ethereum data hex
 *  Returns EthereumPublicKey with prefix
 */
export function toEthereumTxData(value: string | Buffer): EthereumTxData {
  if (isValidEthereumTxData(value)) {
    return isAString(value) ? (ensureHexPrefix(value) as EthereumTxData) : (value as EthereumTxData)
  }
  throw new Error(`Not valid ethereum transaction data:${JSON.stringify(value)}.`)
}

/** Accepts hex string checks if a valid ethereum public key
 *  Returns EthereumPublicKey with prefix
 */
export function toEthereumPublicKey(value: string): EthereumPublicKey {
  if (isValidEthereumPublicKey(value)) {
    return value as EthereumPublicKey
  }
  throw new Error(`Not a valid ethereum public key:${value}.`)
}

/** Accepts hex string checks if a valid ethereum private key
 *  Returns EthereumPrivateKey with prefix
 */
export function toEthereumPrivateKey(value: string): EthereumPrivateKey {
  if (isValidEthereumPrivateKey(value)) {
    return value as EthereumPrivateKey
  }
  throw new Error(`Not a valid ethereum private key:${value}.`)
}

/** Accepts ECDSASignature object or stringified version of it, or hexstring of signature (as returned from eth_sign)
 *  Returns EthereumSignatureNative
 */
export function toEthereumSignatureNative(value: string | ECDSASignature): EthereumSignatureNative {
  let signature: ECDSASignature
  if (isHexString(value)) {
    signature = fromRpcSig(value as string)
  } else {
    signature = typeof value === 'string' ? tryParseJSON(value) : value
  }
  if (isValidEthereumSignatureNative(signature)) {
    return signature as EthereumSignatureNative
  }
  throw new Error(`Not a valid ethereum signature:${JSON.stringify(value)}.`)
}

/** Accepts any signature object or stringified version of it
 *  Returns EthereumSignature string (stringified valid for ETh chain or multisig contract)
 */
export function toEthereumSignature(value: any): EthereumSignature {
  return JSON.stringify(toEthereumSignatureNative(value)) as EthereumSignature
}

/** Accepts hex string checks if a valid ethereum address
 *  Returns EthereumAddress with prefix
 */
export function toEthereumAddress(value: string): EthereumAddress {
  if (isNullOrEmpty(value)) return null
  const prefixedValue = ensureHexPrefix(value)
  if (isValidEthereumAddress(prefixedValue)) {
    return toChainEntityName(prefixedValue)
  }
  throw new Error(`Not a valid ethereum address:${value}.`)
}

/** convert to supported units - e.g. 'eth' to 'ether' */
export function mapAlternativeUnits(unit: string): string {
  const mapped = AlternateUnitMap.find(m => m.from.toLowerCase() === unit?.toLowerCase())?.to
  return mapped || unit
}

/** convert string to EthUnit - throws if not valid value, maps known synonyms ('eth' to 'ether') */
export function toEthUnit(unit: string): EthUnit {
  const mappedUnit = mapAlternativeUnits(unit)
  try {
    return mappedUnit as EthUnit
  } catch (err) {
    throw new Error('Not a valid ethereum unit type.')
  }
}

/** accepts a hexstring or Buffer and returns hexstring (converts buffer to hexstring) */
export function convertBufferToHexStringIfNeeded(value: string | Buffer) {
  return isABuffer(value) ? bufferToHex(value as Buffer) : toHexStringIfNeeded(value)
}

export function privateKeyToAddress(privateKey: string): EthereumAddress {
  const privateKeyBuffer = toEthBuffer(ensureHexPrefix(privateKey))
  return toEthereumAddress(bufferToHex(privateToAddress(privateKeyBuffer)))
}
