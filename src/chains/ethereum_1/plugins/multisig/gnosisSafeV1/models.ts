import BN from 'bn.js'
import { ethers } from 'ethers'
import { EthereumAddress, EthereumRawTransactionAction, EthereumTxData } from '../../../models'
import { SignatureBrand } from '../../../../../models'

export type EthereumMultisigRawTransaction = EthereumRawTransactionAction

export type EthereumGnosisSignatureData = string
export type EthereumGnosisTransactionData = string

export type EthereumGnosisMultisigCreateAccountOptions = {
  owners: EthereumAddress[]
  threshold: number
  saltNonce: number
  gnosisSafeMaster?: EthereumAddress
  proxyFactory?: EthereumAddress
  fallbackHandler?: EthereumAddress
  initializerAction?: InitializerAction
}

export type EthereumGnosisMultisigTransactionOptions = {
  multisigAddress: EthereumAddress
  operation?: number
  nonce?: number
  /** specifies a (non-eth) custom token used to pay gas */
  gasToken?: EthereumAddress
  /** Only used if gasToken is set */
  refundReceiver?: EthereumAddress
  /** Only used if gasToken is set */
  safeTxGas?: number | string
  /** Only used if gasToken is set */
  baseGas?: number | string
  /** Only used if gasToken is set */
  gasPrice?: number | string
}

/** Ethereum action will be called automatically as proxy multisig contract is created
 * Can be used for a similiar functionality as createWithFirstSign
 */
export type InitializerAction = {
  initializerTo?: EthereumAddress
  initializerData?: EthereumTxData
  paymentToken?: EthereumAddress
  paymentAmount?: number
  paymentReceiver?: EthereumAddress
}

export type GnosisSafeTransaction = {
  to: string
  value: string | number | BN | ethers.BigNumber
  data: EthereumGnosisTransactionData
  operation: number
  refundReceiver: string
  safeTxGas: number | string
  baseGas: number | string
  gasPrice: number | string
  gasToken: string
  nonce: number | string
}

/** Adds signatures to GnosisSafeTransaction to support setFromRaw() */
export type GnosisSafeRawTransaction = GnosisSafeTransaction & {
  signatures?: GnosisSafeSignature[]
}

/** Signature object that are gonna be serialized passed for executing sign trx */
export type GnosisSafeSignature = {
  signer: EthereumAddress
  data: EthereumGnosisSignatureData
} & SignatureBrand

export const EIP712_SAFE_TX_TYPE = {
  // "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
  SafeTx: [
    { type: 'address', name: 'to' },
    { type: 'uint256', name: 'value' },
    { type: 'bytes', name: 'data' },
    { type: 'uint8', name: 'operation' },
    { type: 'uint256', name: 'safeTxGas' },
    { type: 'uint256', name: 'baseGas' },
    { type: 'uint256', name: 'gasPrice' },
    { type: 'address', name: 'gasToken' },
    { type: 'address', name: 'refundReceiver' },
    { type: 'uint256', name: 'nonce' },
  ],
}
