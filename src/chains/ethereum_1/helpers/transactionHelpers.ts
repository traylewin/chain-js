import Web3 from 'web3'
import { BN, bufferToHex } from 'ethereumjs-util'
import { isAString, isNullOrEmpty } from '../../../helpers'
import { EthUnit, EthereumActionContract, EthereumMultiValue } from '../models'
import { ZERO_HEX, EMPTY_HEX, ZERO_ADDRESS } from '../ethConstants'
import { toEthereumTxData } from './cryptoModelHelpers'

/** Converts functionSignature to hexadecimal string */
export function functionSignatureToHex(functionSignature: string): string {
  const web3 = new Web3()
  return web3.eth.abi.encodeFunctionSignature(functionSignature)
}

/** Finds the method from abi json object array
 * Returns the methodName with inputSignature in a string format (myMethod(uint256,string))
 */
export function abiToFunctionSignature(methodName: string, abi: any[]): string {
  let inputSignature = ''
  if (isNullOrEmpty(methodName)) {
    throw new Error('abiToFunctionSignature - methodName missing')
  }
  const method = abi.find(m => m.name === methodName)
  if (isNullOrEmpty(method)) {
    throw new Error(`abiToFunctionSignature - method:${methodName} not found in abi`)
  }
  method.inputs.forEach((input: { type: any }) => {
    inputSignature += `${input?.type},`
  })
  inputSignature = inputSignature.slice(0, -1)
  return `${methodName}(${inputSignature})`
}

/** Uses web3-utils toWei conversion */
export function toWei(amount: BN | number, fromType: EthUnit) {
  const web3 = new Web3()
  return web3.utils.toWei(new BN(amount), fromType)
}

/** convert a decimal string from fromType to Wei units
 *  Returns a string */
export function toWeiString(amount: string, fromType: EthUnit): string {
  const web3 = new Web3()
  return web3.utils.toWei(amount, fromType)
}

export function fromWeiString(wei: string, toType: EthUnit): string {
  const web3 = new Web3()
  return web3.utils.fromWei(wei, toType)
}

export function toEthString(amount: string, fromType: EthUnit): string {
  const wei = toWeiString(amount, fromType)
  const eth = fromWeiString(wei, EthUnit.Ether)
  return eth
}

/** Return true if a string value and not hex */
export function isDecimalString(value: EthereumMultiValue): boolean {
  return isAString(value) && !(value as string).startsWith('0x')
}

/** Converts wei amount to Gwei
 *  1 Gwei = 1000000000 wei */
export function toGweiFromWei(amount: number | BN) {
  return 0.000000001 * (amount as number)
}

/** Checks if nullOrEmpty and ethereum spesific hexadecimal and Buffer values that implies empty */
export function ethereumTrxArgIsNullOrEmpty(obj: any) {
  if (
    isNullOrEmpty(obj) ||
    obj === 0 ||
    obj === ZERO_HEX ||
    obj === EMPTY_HEX ||
    obj === ZERO_ADDRESS ||
    obj === Buffer.from(ZERO_HEX, 'hex')
  )
    return true
  if (Buffer.isBuffer(obj) && bufferToHex(obj) === EMPTY_HEX) return true

  return false
}

/** Generates hexadecimal string for transaction data from EthereumActionContract */
export function generateDataFromContractAction(contractAction: EthereumActionContract) {
  const { abi, method, parameters } = contractAction
  const web3 = new Web3()
  const contract = new web3.eth.Contract(abi)
  const methodHex = functionSignatureToHex(abiToFunctionSignature(method, abi))
  return toEthereumTxData(contract.methods[methodHex](...parameters).encodeABI())
}

/** if value is null or a empty Eth value (e.g. '0x00..') returns null, otherwise return the value passed-in */
export function nullifyIfEmptyEthereumValue(value: any) {
  if (ethereumTrxArgIsNullOrEmpty(value)) return null
  return value
}
