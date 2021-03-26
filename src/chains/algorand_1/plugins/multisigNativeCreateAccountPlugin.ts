/* eslint-disable max-classes-per-file */
import * as algosdk from 'algosdk'
import { MultisigTransaction } from '../../../interfaces/multisigPlugin/multisigTransaction'
import { throwNewError } from '../../../errors'
import { byteArrayToHexString, hexStringToByteArray, isNullOrEmpty, uint8ArraysAreEqual } from '../../../helpers'
// eslint-disable-next-line import/no-cycle

import {
  AlgorandAddress,
  AlgorandMultiSignatureMsigStruct,
  AlgorandMultiSignatureStruct,
  AlgorandMultiSigOptions,
  AlgorandPrivateKey,
  AlgorandPublicKey,
  AlgorandRawTransactionMultisigStruct,
  AlgorandSignature,
  AlgorandTxActionSdkEncoded,
  AlgorandTxSignResults,
} from '../models'
import { getAlgorandPublicKeyFromPrivateKey } from '../algoCrypto'
import {
  assertValidSignatures,
  getPublicKeyForAddress,
  isValidTxSignatureForPublicKey,
  toAddressFromPublicKey,
  toAlgorandPublicKey,
  toAlgorandSignatureFromRawSig,
  toPublicKeyFromAddress,
  toRawTransactionFromSignResults,
} from '../helpers'

export interface AlgorandMultisigPluginInput {
  multiSigOptions: AlgorandMultiSigOptions
  raw: AlgorandRawTransactionMultisigStruct
}

export class AlgorandMultisigTransaction implements MultisigTransaction {
  private _rawTransaction: any

  private _multiSigOptions: AlgorandMultiSigOptions

  constructor(input: AlgorandMultisigPluginInput) {
    const { multiSigOptions, raw } = input
    if (raw) {
      this.setRawTransactionFromSignResults({ txID: null, blob: algosdk.encodeObj(raw) })
    } else {
      this._multiSigOptions = multiSigOptions
    }
  }

  get multiSigOptions() {
    if (!this._multiSigOptions && this._rawTransaction?.msig) {
      this._multiSigOptions = this.multiSigOptionsFromRaw
    }
    return this._multiSigOptions
  }

  /** Multisig transaction options */
  get multiSigOptionsFromRaw(): AlgorandMultiSigOptions {
    return this.rawTransaction?.msig ? this.multisigOptionsFromRawTransactionMultisig(this.rawTransaction?.msig) : null
  }

  /** Get the raw transaction (either regular or multisig) */
  get rawTransaction(): AlgorandRawTransactionMultisigStruct {
    return this._rawTransaction
  }

  /** Whether the raw transaction body has been set or prepared */
  get hasRaw(): boolean {
    return !!this.rawTransaction
  }

  /** Throws if no raw transaction body */
  private assertHasRaw(): void {
    if (!this.hasRaw) {
      throwNewError('Transaction doesnt have a raw transaction body. Call prepareToBeSigned() or use setFromRaw().')
    }
  }

  /** Generate the raw transaction body using the actions attached
   *  Also adds a header to the transaction that is included when transaction is signed
   */
  public async prepareToBeSigned(rawTransaction: AlgorandRawTransactionMultisigStruct): Promise<void> {
    this._rawTransaction = {
      txn: rawTransaction,
      msig: {
        v: this.multiSigOptions.version,
        thr: this.multiSigOptions.threshold,
        subsig: this.multiSigOptions.addrs.map(addr => ({
          pk: Buffer.from(hexStringToByteArray(toPublicKeyFromAddress(addr))),
        })),
      },
    }
  }

  /** Determine standard multisig options from raw msig struct */
  private multisigOptionsFromRawTransactionMultisig(msig: AlgorandMultiSignatureMsigStruct): AlgorandMultiSigOptions {
    if (isNullOrEmpty(msig)) return null
    const addrs = msig.subsig.map(sig => toAddressFromPublicKey(toAlgorandPublicKey(byteArrayToHexString(sig.pk))))
    return {
      version: msig.v,
      threshold: msig.thr,
      addrs,
    }
  }

  /** Signatures attached to transaction */
  get signatures(): AlgorandSignature[] {
    const signatures = (this.rawTransaction as AlgorandRawTransactionMultisigStruct)?.msig?.subsig
      ?.filter(subsig => !!subsig.s)
      ?.map(subsig => toAlgorandSignatureFromRawSig(subsig.s))

    return signatures || null
  }

  /** Whether there is an attached signature for the provided publicKey */
  public hasSignatureForPublicKey(publicKey: AlgorandPublicKey): boolean {
    const pks = this.getPublicKeysForSignaturesFromRawTx() || []
    return !!pks.find(key => key === publicKey)
  }

  /** Returns address, for which, a matching signature must be attached to transaction */
  public get missingSignatures(): AlgorandAddress[] {
    const missingSignatures =
      this.requiredAuthorizations?.filter(auth => !this.hasSignatureForPublicKey(toPublicKeyFromAddress(auth))) || []
    const signaturesAttachedCount = (this.requiredAuthorizations?.length || 0) - missingSignatures.length

    // check if number of signatures present are greater then or equal to multisig threshold
    // If threshold reached, return null for missing signatures
    return signaturesAttachedCount >= this.multiSigOptions.threshold ? null : missingSignatures
  }

  /** Returns public keys of the signatures attached to the signed transaction
   *  For a typical transaction, there is only signature, multiSig transactions can have more */
  public getPublicKeysForSignaturesFromRawTx(): AlgorandPublicKey[] {
    const { msig } = this._rawTransaction
    // drop empty values in subsig
    const multiSigs = msig?.subsig?.filter((sig: AlgorandMultiSignatureStruct) => !!sig?.s) || []
    return multiSigs?.map((sig: AlgorandMultiSignatureStruct) => toAlgorandPublicKey(byteArrayToHexString(sig.pk)))
  }

  /** Add signatures to raw transaction
   *  Only allows signatures that use the publicKey(s) required for the transaction (from accnt, rekeyed spending key, or mulisig keys)
   *  Signatures are hexstring encoded Uint8Array */
  addSignatures = (signaturesIn: AlgorandSignature[]): void => {
    const signatures = signaturesIn || []
    this.assertHasRaw()
    assertValidSignatures(signatures)
    // Handle multisig transaction
    if (isNullOrEmpty(signatures) && this?._rawTransaction?.msig) {
      // wipe out all the signatures in the subsig array (just set the public key)
      this._rawTransaction.msig.subsig = this._rawTransaction.msig.subsig.map((ss: any) => ({
        pk: ss.pk,
      }))
    }
    // For every signature provided...
    signatures.forEach(sig => {
      // look for a match with any of the publicKeys in the multiSigOptions
      const addressForSig = this.multiSigOptions.addrs.find(addr =>
        isValidTxSignatureForPublicKey(sig, getPublicKeyForAddress(addr)),
      )
      if (addressForSig) {
        const newPubKey = hexStringToByteArray(getPublicKeyForAddress(addressForSig))
        const newSig = hexStringToByteArray(sig)
        // set signature for publickey in subsig array
        this._rawTransaction.msig.subsig.find((ss: any) => uint8ArraysAreEqual(ss.pk, newPubKey)).s = newSig
      } else {
        const errorMsg = `The signature: ${sig} isnt valid for this transaction using any of publicKeys specified in multiSigOptions: ${JSON.stringify(
          this.multiSigOptions,
        )}.`
        throwNewError(errorMsg)
      }
    })
  }

  /** Returns array of the required addresses for a transaction/multisig transaction
   *  Returns the from address in the action or addresses from multisig options for multisig transaction
   */
  public get requiredAuthorizations(): AlgorandAddress[] {
    return this?.multiSigOptions?.addrs || []
  }

  /** Set the raw trasaction properties from the packed results from using Algo SDK to sign tx */
  public setRawTransactionFromSignResults(signResults: AlgorandTxSignResults) {
    const { transaction } = toRawTransactionFromSignResults(signResults)
    this._rawTransaction = transaction as AlgorandRawTransactionMultisigStruct
  }

  async sign(
    actionEncodedForSdk: AlgorandTxActionSdkEncoded,
    privateKeys: AlgorandPrivateKey[],
    transactionId: string,
  ) {
    let signedMergedTransaction: AlgorandTxSignResults
    const signedTransactionResults: AlgorandTxSignResults[] = []
    // start with existing multiSig transaction/signatures (if any)
    if (!isNullOrEmpty(this._rawTransaction)) {
      signedTransactionResults.push({
        txID: transactionId,
        blob: algosdk.encodeObj(this._rawTransaction),
      })
    }
    // add signatures for each private key provided
    privateKeys.forEach(key => {
      const privateKey = hexStringToByteArray(key)
      const privateKeyAddress = toAddressFromPublicKey(getAlgorandPublicKeyFromPrivateKey(key))
      if (!this.multiSigOptions.addrs.includes(privateKeyAddress)) {
        throwNewError(
          `Cant sign multisig transaction the private key of address ${privateKeyAddress} - it doesnt match an address in multisig options: ${this.multiSigOptions.addrs}`,
        )
      }
      const signResults: AlgorandTxSignResults = algosdk.signMultisigTransaction(
        actionEncodedForSdk,
        this.multiSigOptions,
        privateKey,
      )
      signedTransactionResults.push(signResults)
    })
    // if more than one sig, use the sdk's merge function
    if (signedTransactionResults.length > 1) {
      const { txID } = signedTransactionResults[0] // txID should be the same for all results
      const blob = algosdk.mergeMultisigTransactions(signedTransactionResults.map(r => r.blob))
      signedMergedTransaction = { txID, blob }
    } else {
      // eslint-disable-next-line prefer-destructuring
      signedMergedTransaction = signedTransactionResults[0]
    }
    // set results to class
    this.setRawTransactionFromSignResults(signedMergedTransaction)
  }
}
