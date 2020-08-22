// eslint-disable-next-line import/no-extraneous-dependencies
import { TransactionReceipt } from 'web3-core'
import { EthereumMultiValue } from './generalModels'

export type EthereumAbi = any[]
/** Information needed to generate Trx Data to invoke desired smart contract action */
export type EthereumActionContract = {
  abi: any
  method: string
  parameters: (EthereumMultiValue | EthereumMultiValue[])[]
}

export type EthereumAddress = string

export type EthereumMethodName = EthereumMultiValue & string

/** Transaction with serialized buffer data - ready to be signed and sent to chain */
export type EthereumRawTransaction = {
  nonce?: Buffer
  gasPrice?: Buffer
  gasLimit?: Buffer
  to?: Buffer
  value?: Buffer
  data?: Buffer
  v?: Buffer
  r?: Buffer
  s?: Buffer
}

export type EthereumHexTransaction = {
  nonce?: string
  gasPrice?: string
  gasLimit?: string
  to?: string
  value?: string
  data?: string
}

export type EthereumActionHelperInput = {
  nonce?: EthereumMultiValue
  gasPrice?: EthereumMultiValue
  gasLimit?: EthereumMultiValue
  from?: EthereumAddress
  to?: EthereumMultiValue
  value?: EthereumMultiValue
  data?: EthereumMultiValue & (string | Buffer)
  v?: EthereumMultiValue
  r?: EthereumMultiValue
  s?: EthereumMultiValue
  contract?: EthereumActionContract
}

/** Properties of an ETH transaction action
 *  Can be used to create or compose a new ETH action
 *  to and value - must both be present as a pair
 *  data or contract - to create an action, optionally provide one but not both
 *  contract property used only to generate data prop when creating an new action */
export type EthereumTransactionAction = {
  to?: EthereumAddress
  from?: EthereumAddress
  value?: string | number
  data?: EthereumTxData
  gasPrice?: string
  gasLimit?: string
  contract?: EthereumActionContract
}

/** Transaction properties that contain the fee & priority info */
export type EthereumTransactionHeader = {
  nonce?: EthereumMultiValue
  gasPrice?: EthereumMultiValue
  gasLimit?: EthereumMultiValue
}

/** Transaction 'header' options set to chain along with transaction */
export type EthereumTransactionOptions = {
  nonce?: EthereumMultiValue
  gasPrice?: EthereumMultiValue
  gasLimit?: EthereumMultiValue
  chain: number | string
  hardfork: EthereumMultiValue & string
}

/** Hexadecimal format of contrat action data */
export type EthereumTxData = string & EthereumTxDataBrand

/** Brand signifiying a valid value - assigned by using toEthereumTxData */
export enum EthereumTxDataBrand {
  _ = '',
}

/** Payload returned after sending transaction to chain */
export type EthereumTxResult = {
  transactionId: string
  chainResponse: EthereumTxChainResponse
}

/** Response from chain after sending transaction */
export type EthereumTxChainResponse = TransactionReceipt

export enum EthereumTxPriority {
  Slow = 'slow',
  Average = 'average',
  Fast = 'fast',
}
