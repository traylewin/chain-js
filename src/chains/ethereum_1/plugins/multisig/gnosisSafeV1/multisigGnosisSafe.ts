import { isNullOrEmpty } from '../../../../../helpers'
import { throwNewError } from '../../../../../errors'
import { isNullOrEmptyEthereumValue, toEthereumEntityName } from '../../../helpers'
import { EthereumAddress, EthereumEntityName, EthereumPrivateKey, EthereumTransactionAction } from '../../../models'
import { EthereumMultisigPlugin, EthereumMultisigPluginOptions } from '../ethereumMultisigPlugin'
import {
  approveSafeTransactionHash,
  getCreateProxyAddressAndTransaction,
  getEthersJsonRpcProvider,
  getGnosisSafeContract,
  getSafeExecuteTransaction,
  getSafeOwnersAndThreshold,
  rawTransactionToSafeTx,
  signSafeTransactionHash,
} from './helpers'
import {
  EthereumGnosisSafeMultisigOptions,
  EthereumMultisigRawTransaction,
  GnosisSafeSignature,
  GnosisSafeTransaction,
} from './models'
import { PluginType, Plugin } from '../../../../../interfaces/plugin'

// export class Plugin {
//   /** Plugin name */
//   public name: string

//   /** Plugin type */
//   public type: PluginType

//   /** Plugin options */
//   private _options: any

//   /** Chainstate - will be set automatically when plugin installed - do not set this */
//   public chainState: any

//   constructor(options: any) {
//     this._options = options
//   }

//   /** Initializes plugin using options */
//   init(options: any) {} // eslint-disable-line @typescript-eslint/no-unused-vars
// }

export class GnosisSafeMultisigPlugin extends Plugin implements EthereumMultisigPlugin {
  private _multisigOptions: EthereumGnosisSafeMultisigOptions

  private _multisigAddress: EthereumAddress

  private _rawTransaction: EthereumMultisigRawTransaction

  private _safeTransaction: GnosisSafeTransaction

  private _signatures: GnosisSafeSignature[]

  private _createTransaction: EthereumTransactionAction

  private _owners: EthereumAddress[]

  public requiresTransaction = true

  constructor(options: EthereumMultisigPluginOptions) {
    super(options)
    const { multisigOptions } = options
    this._multisigOptions = multisigOptions
    this._multisigAddress = multisigOptions?.pluginOptions?.multisigAddress
  }

  public name = 'Gnosis V1 Multisig Plugin'

  public type = PluginType.MultiSig

  // run initialization steps
  async init(options: EthereumMultisigPluginOptions) {
    super.init(options)
  }

  get multisigOptions(): EthereumGnosisSafeMultisigOptions {
    return this._multisigOptions
  }

  /** Chain-specific and time-sensitive transaction header */
  multisigOptionsFromRaw: any

  /** Get the raw transaction (either regular or multisig) */
  get rawTransaction(): EthereumMultisigRawTransaction {
    return this._rawTransaction
  }

  /** Whether the raw transaction body has been set or prepared */
  get hasRaw(): boolean {
    return !!this.rawTransaction
  }

  get safeTransaction(): GnosisSafeTransaction {
    return this._safeTransaction
  }

  get multisigAddress(): EthereumAddress {
    return this.multisigOptions?.pluginOptions?.multisigAddress
  }

  get owners(): string[] {
    if (isNullOrEmpty(this._owners)) {
      throwNewError('Owners are not set. Call prepareToBeSigned() or multisigContract.getOwners()')
    }
    return this._owners
  }

  get multisigContract(): any {
    const { pluginOptions } = this.multisigOptions
    const { chainUrl } = pluginOptions
    const ethersProvier = getEthersJsonRpcProvider(chainUrl)
    return getGnosisSafeContract(ethersProvier, this.multisigAddress)
  }

  /** Returns address, for which, a matching signature must be attached to transaction */
  public get missingSignatures(): EthereumAddress[] {
    const missingSignatures =
      this.requiredAuthorizations?.filter(address => !this.hasSignatureForAddress(address)) || []

    const signaturesAttachedCount = (this.requiredAuthorizations?.length || 0) - missingSignatures.length

    // check if number of signatures present are greater then or equal to multisig threshold
    // If threshold reached, return null for missing signatures
    return signaturesAttachedCount >= this.multisigOptions.weight ? null : missingSignatures
  }

  /** Signatures attached to transaction */
  get signatures(): GnosisSafeSignature[] {
    return this._signatures
  }

  /** Returns array of the required addresses for a transaction/multisig transaction
   *  Returns the from address in the action or addresses from multisig options for multisig transaction
   */
  public get requiredAuthorizations(): EthereumAddress[] {
    return this?.multisigOptions?.addrs || []
  }

  /** Checks if signature addresses match with multisig owners and adds to the signatures array */
  async addSignatures(signaturesIn: GnosisSafeSignature[]) {
    signaturesIn.forEach(signature => {
      if (!this.multisigOptions.addrs.includes(signature.signer))
        throwNewError(`Signature data:${signature.data} does not belong to any of the multisig owner addresses`)
    })
    this._signatures.concat(signaturesIn)
    if (isNullOrEmpty(this.missingSignatures)) {
      await this.setRawTransaction()
    }
  }

  async approveAndAddApprovalSignature(privateKeys: EthereumPrivateKey[]) {
    const signResults = this._signatures
    privateKeys.forEach(async pk => {
      const result = await approveSafeTransactionHash(pk, this.safeTransaction, this.multisigOptions)
      signResults.push(result)
    })
    this._signatures = signResults
  }

  public async getNonce(): Promise<number> {
    const nonce = (await this.multisigContract.nonce()).toNumber()
    return nonce
  }

  /** Whether there is an attached signature for the provided publicKey */
  public hasSignatureForAddress(address: EthereumAddress): boolean {
    let includes = false
    this.signatures?.forEach(signature => {
      if (signature.signer === address) includes = true
    })
    return includes
  }

  /** Generate the raw transaction body using the actions attached
   *  Also adds a header to the transaction that is included when transaction is signed
   */
  public async prepareToBeSigned(rawTransaction: EthereumMultisigRawTransaction): Promise<void> {
    await this.verifyAndSetMultisigAddress()
    await this.verifyAndSetMultisigOwners()
    this._safeTransaction = await rawTransactionToSafeTx(rawTransaction, this.multisigOptions)
  }

  public async sign(privateKeys: EthereumPrivateKey[]) {
    const signResults = this._signatures || []
    await Promise.all(
      privateKeys.map(async pk => {
        const result = await signSafeTransactionHash(pk, this.safeTransaction, this.multisigOptions)
        signResults.push(result)
      }),
    )
    this._signatures = signResults
    if (isNullOrEmpty(this.missingSignatures)) {
      await this.setRawTransaction()
    }
  }

  private async setRawTransaction() {
    this._rawTransaction = await getSafeExecuteTransaction(this.multisigOptions, this.safeTransaction, this.signatures)
  }

  public validate(): void {
    if (!this.safeTransaction) {
      throwNewError('safeTransaction is missing. Call prepareToBeSigned()')
    }
  }

  public async verifyAndSetMultisigAddress() {
    const { pluginOptions } = this.multisigOptions
    const { gnosisSafeMasterAddress, proxyFactoryAddress, chainUrl, nonce, multisigAddress } = pluginOptions
    let calculatedAddress = multisigAddress
    if (
      !isNullOrEmpty(chainUrl) &&
      !isNullOrEmptyEthereumValue(gnosisSafeMasterAddress) &&
      !isNullOrEmptyEthereumValue(proxyFactoryAddress) &&
      !isNullOrEmpty(nonce)
    ) {
      const { address } = await getCreateProxyAddressAndTransaction(this.multisigOptions)
      if (!isNullOrEmptyEthereumValue(multisigAddress) && address !== multisigAddress) {
        throwNewError('multisigAddress and multisigOptions does not match!')
      }
      calculatedAddress = address
    }
    this._multisigOptions.pluginOptions.multisigAddress = calculatedAddress
  }

  async verifyAndSetMultisigOwners() {
    let owners = this.multisigOptions?.addrs
    if (!isNullOrEmptyEthereumValue(this.multisigAddress)) {
      const { owners: contractOwners } = await getSafeOwnersAndThreshold(this.multisigContract)
      owners.forEach(ownr => {
        if (!contractOwners.includes(ownr))
          throwNewError(' multisigOptions.addrs does not match with owners on contract')
      })
      owners = contractOwners
    }
    this._owners = owners
  }

  get accountName(): EthereumEntityName {
    if (!this._multisigAddress) {
      if (!this.multisigOptions?.pluginOptions?.multisigAddress) {
        return null
      }
      this._multisigAddress = this.multisigOptions?.pluginOptions?.multisigAddress
    }

    return toEthereumEntityName(this._multisigAddress)
  }

  get transaction(): EthereumTransactionAction {
    if (!this._createTransaction) throwNewError('Transaction needs to be set using generateKeysIfNeeded() function')
    return this._createTransaction
  }

  public async generateKeysIfNeeded() {
    const { address, transaction } = await getCreateProxyAddressAndTransaction(this.multisigOptions)
    this._multisigOptions.pluginOptions.multisigAddress = address
    this._multisigAddress = address
    this._createTransaction = transaction
  }
}
