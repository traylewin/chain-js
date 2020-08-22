import { Transaction as EthereumJsTx } from 'ethereumjs-tx'
import { bufferToHex } from 'ethereumjs-util'
import { isNullOrEmpty } from '../../helpers'
import {
  ethereumTrxArgIsNullOrEmpty,
  generateDataFromContractAction,
  toEthereumTxData,
  isValidEthereumAddress,
} from './helpers'
import {
  EthereumMultiValue,
  EthereumTxData,
  EthereumActionContract,
  EthereumRawTransaction,
  EthereumHexTransaction,
  EthereumActionHelperInput,
} from './models'
import { ZERO_HEX, ZERO_ADDRESS } from './ethConstants'
import { throwNewError } from '../../errors'

/** Helper class to ensure transaction actions properties are set correctly */
export class EthereumActionHelper {
  private _data: EthereumTxData

  private _to: EthereumMultiValue

  private _value: EthereumMultiValue

  private _from: EthereumMultiValue

  private _contract: EthereumActionContract

  private _raw: EthereumRawTransaction

  private _hex: EthereumHexTransaction

  /** Creates a new Action from 'human-readable' transfer or contact info
   *  OR from 'raw' data property
   *  Allows access to human-readable properties (method, parameters) or raw data (hex) */
  constructor(actionInput: EthereumActionHelperInput) {
    this.assertAndValidateEthereumActionInput(actionInput)
    this.setEthereumRawTrx()
    this.setEthereumHexTrx()
  }

  /** apply rules for imput params, set class private properties, throw if violation */
  private assertAndValidateEthereumActionInput(actionInput: EthereumActionHelperInput) {
    const { to, from, value, contract, data } = actionInput

    this._to = isNullOrEmpty(to) ? ZERO_ADDRESS : to
    this._from = isNullOrEmpty(from) ? ZERO_ADDRESS : from
    this._value = isNullOrEmpty(value) ? ZERO_HEX : value

    if (isNullOrEmpty(from)) {
      this._from = ZERO_ADDRESS
    } else if (isValidEthereumAddress(from)) {
      this._from = from
    } else {
      throwNewError('From is not a valid ethereum address')
    }

    // cant provide both contract and data properties
    if (!ethereumTrxArgIsNullOrEmpty(contract) && !ethereumTrxArgIsNullOrEmpty(data)) {
      throwNewError('You can provide either data or contract but not both')
    }

    // set data from provided data or contract properties
    if (!ethereumTrxArgIsNullOrEmpty(data)) this._data = toEthereumTxData(data)
    else if (!ethereumTrxArgIsNullOrEmpty(contract)) {
      this._data = generateDataFromContractAction(contract)
      this._contract = contract
    } else this._data = toEthereumTxData(ZERO_HEX)
  }

  private setEthereumRawTrx() {
    const ethTx = new EthereumJsTx({ to: this._to, value: this._value, data: this._data })
    this._raw = {
      nonce: ethTx.nonce,
      gasLimit: ethTx.gasLimit,
      gasPrice: ethTx.gasPrice,
      to: ethTx.to,
      value: ethTx.value,
      data: ethTx.data,
      v: ethTx.v,
      r: ethTx.r,
      s: ethTx.s,
    }
  }

  private setEthereumHexTrx() {
    const ethTx = new EthereumJsTx({ to: this._to, value: this._value, data: this._data })
    this._hex = {
      nonce: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.nonce)) ? null : bufferToHex(ethTx.nonce),
      gasLimit: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.gasLimit)) ? null : bufferToHex(ethTx.gasLimit),
      gasPrice: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.gasPrice)) ? null : bufferToHex(ethTx.gasPrice),
      to: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.to)) ? null : bufferToHex(ethTx.to),
      value: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.value)) ? null : bufferToHex(ethTx.value),
      data: ethereumTrxArgIsNullOrEmpty(bufferToHex(ethTx.data)) ? null : bufferToHex(ethTx.data),
    }
  }

  /** Returns 'hex' data */
  get data() {
    return this._hex.data
  }

  /** Checks is data value is empty or implying 0 */
  get hasData(): boolean {
    return !ethereumTrxArgIsNullOrEmpty(this._data)
  }

  /** Action properties including raw data */
  public get raw(): EthereumRawTransaction {
    return this._raw
  }

  /** Action properties including raw data */
  public get hex(): EthereumHexTransaction {
    return this._hex
  }

  /** Action properties including raw data */
  public get contract(): EthereumActionContract {
    return this._contract
  }
}
