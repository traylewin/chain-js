import {
  AlgorandAddress,
  AlgorandEntityName,
  AlgorandPrivateKey,
  AlgorandPublicKey,
  AlgorandRawTransactionMultisigStruct,
  AlgorandSignature,
  AlgorandTxEncodedForChain,
} from '../../models'
import { MultisigPlugin } from '../../../../interfaces'
// import { AlgorandNativeMultisigOptions } from './native/models'

export interface AlgorandMultisigPlugin extends MultisigPlugin {
  name: string

  init(options: any): Promise<void>
  // ----- TRANSACTION Members

  multisigOptions: any

  owners: string[]

  threshold: number

  /** Raw transaction body
   *  Note: Set via prepareToBeSigned() or setFromRaw() */
  rawTransaction: AlgorandRawTransactionMultisigStruct

  /** Whether transaction has been prepared for signing (has raw body) */
  hasRaw: boolean

  missingSignatures: AlgorandAddress[]

  /** An array of the unique set of authorizations needed for all actions in transaction */
  requiredAuthorizations: AlgorandAddress[]

  /** Signatures attached to transaction */
  signatures: AlgorandSignature[]

  getPublicKeysForSignaturesFromRawTx(): AlgorandPublicKey[]

  /** Add a signature to the set of attached signatures. Automatically de-duplicates values. */
  addSignatures(signature: AlgorandSignature[]): void

  prepareToBeSigned(trxEncodedForChain: AlgorandTxEncodedForChain): Promise<void>

  /** Sign the transaction body with private key(s) and add to attached signatures */
  sign(privateKeys: AlgorandPrivateKey[]): Promise<void>

  validate(): void

  // ----- CREATE ACCOUNT Members

  accountName: AlgorandEntityName

  /** Not supported */
  transaction: any

  requiresTransaction: boolean

  generateKeysIfNeeded(): Promise<void>
}
