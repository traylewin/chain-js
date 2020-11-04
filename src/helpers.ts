import BigNumber from 'bignumber.js'
import BN from 'bn.js'
import { parse, stringify } from 'flatted'
import { DEFAULT_TOKEN_PRECISION, TRANSACTION_ENCODING } from './constants'
import { ChainEntityName, IndexedObject, ChainEndpoint } from './models'

export function isAUint8Array(obj: any) {
  return obj !== undefined && obj !== null && obj.constructor === Uint8Array
}

export function isAUint8ArrayArray(obj: any) {
  if (obj === undefined || obj === null || !Array.isArray(obj)) {
    return false
  }
  return (obj as Array<any>).every(isAUint8Array)
}

export function isABuffer(value: any) {
  if (value === undefined || value === null) return false
  return Buffer.isBuffer(value)
}

export function isNullOrEmpty(obj: any): boolean {
  if (obj === undefined) {
    return true
  }
  if (obj === null) {
    return true
  }

  if (isAUint8Array(obj)) {
    return obj.length === 0
  }

  if (isABuffer(obj)) {
    return obj.byteLength === 0
  }

  // Check for an empty array too
  // eslint-disable-next-line no-prototype-builtins
  if (obj.hasOwnProperty('length')) {
    if (obj.length === 0) {
      return true
    }
  }
  return Object.keys(obj).length === 0 && obj.constructor === Object
}

export function getArrayIndexOrNull(array: any[] = [], index: number) {
  if (array.length > index && !isNullOrEmpty(array[index])) {
    return array[index]
  }
  return null
}

// uses flatted library to allow stringifing on an object with circular references
// NOTE: This does not produce output similar to JSON.stringify, it has it's own format
// to allow you to stringify and parse and get back an object with circular references
export function stringifySafe(obj: any): any {
  return stringify(obj)
}

// this is the inverse of stringifySafe
// if converts a specially stringifyied string (created by stringifySafe) back into an object
export function parseSafe(string: string): any {
  return parse(string)
}

// convert data into buffer object (optional encoding)
export function toBuffer(data: any, encoding: BufferEncoding = TRANSACTION_ENCODING) {
  if (!data) return null
  return Buffer.from(data, encoding)
}

// convert buffer into a string
export function bufferToString(buffer: Buffer, encoding: string = 'utf8') {
  if (!buffer) return null
  return buffer.toString(encoding)
}

// convert buffer into a Uint8Array
export function bufferToUint8Array(buffer: Buffer) {
  if (!buffer) return null
  return new Uint8Array(buffer.buffer)
}

export function uint8ArraysAreEqual(array1: Uint8Array, array2: Uint8Array) {
  return Buffer.compare(array1, array2) === 0
}

/** filter values in array down to an array of a single, uniques value
 * e.g. if array = [{value:'A', other}, {value:'B'}, {value:'A', other}]
 * distinct(array, uniqueKey:'value') => ['A','B']
 */
export function distinctValues(values: Array<any>, uniqueKey: string) {
  return [...new Set(values.map(item => item[uniqueKey]))]
}

/** combine one array into another but only include unique values */
export function addUniqueToArray<T>(array: T[], values: T[]) {
  const arrayFixed = array ?? []
  const valuesFixed = values ?? []
  const set = new Set<T>([...arrayFixed, ...valuesFixed])
  return [...set]
}

export function isAString(value: any) {
  if (!value) {
    return false
  }
  return typeof value === 'string' || value instanceof String
}

export function isADate(value: any) {
  return value instanceof Date
}

export function isABoolean(value: any) {
  return typeof value === 'boolean' || value instanceof Boolean
}

export function isANumber(value: any) {
  if (Number.isNaN(value)) return false
  return typeof value === 'number' || value instanceof Number
}

export function isAnObject(obj: any) {
  return !isNullOrEmpty(obj) && typeof obj === 'object'
}

/** Typescript Typeguard to verify that the value is in the enumType specified  */
export function isInEnum<T>(enumType: T, value: any): value is T[keyof T] {
  return Object.values(enumType).includes(value as T[keyof T])
}

export function getUniqueValues<T>(array: T[]) {
  return Array.from(new Set(array.map(item => JSON.stringify(item)))).map(item => JSON.parse(item))
}

export function trimTrailingChars(value: string, charToTrim: string) {
  if (isNullOrEmpty(value) || !isAString(value)) return value
  const regExp = new RegExp(`${charToTrim}+$`)
  return value.replace(regExp, '')
}

export const removeEmptyValuesInJsonObject = (obj: { [x: string]: any }) => {
  Object.keys(obj).forEach(key => {
    if (obj[key] && typeof obj[key] === 'object') removeEmptyValuesInJsonObject(obj[key])
    // recurse
    // eslint-disable-next-line no-param-reassign
    else if (isNullOrEmpty(obj[key])) delete obj[key] // delete the property
  })
}

export const notImplemented = () => {
  throw new Error('Not Implemented')
}

export const notSupported = (description: string) => {
  throw new Error(`Not Supported ${description}`)
}

/**
 * Returns an the first value from the array if only 1 exists, otherwise returns null
 */
export function getFirstValueIfOnlyOneExists(array: any[]): any {
  const lengthRequirement = 1
  if (!isNullOrEmpty(array) && array.length === lengthRequirement) {
    const [firstValue] = array
    return firstValue
  }

  return null
}

/** Always returns true (unless empty */
export function isValidChainEntityName(str: ChainEntityName | string): str is ChainEntityName {
  if (isNullOrEmpty(str)) return false
  return true
}

/** Coerce string into ChainEntityName */
export function toChainEntityName(name: string): ChainEntityName {
  if (name === '') {
    return null
  }
  if (isValidChainEntityName(name)) {
    return name
  }
  throw new Error(`Should not get here. toChainEntityName name:${name}`)
}

/* Provides a wrapper around a fetch object to allow injection of options into each fetch request
   Returns fetch reponse */
export function fetchWrapper(fetchService: any, globalOptions = {}) {
  // standard fetch interface so that this can be plugged-into any code that accepts a fetch object type
  return async function fetch(url: any, options = {}): Promise<any> {
    const fetchOptions = { ...globalOptions, ...options }
    const response = await fetchService(url, fetchOptions)
    return response
  }
}

/** Conver an array to a JSON object e.g. [{'key1':value1}, {'key2':value2}] =>  {{'key1':value1}, {'key2':value2}} */
export function arrayToObject(array: IndexedObject[]) {
  const result: any = {}
  if (isNullOrEmpty(array)) return null
  array.forEach(header => {
    const key = Object.keys(header)[0]
    result[key] = header[key]
  })
  return result
}

/** returns the required header from the headers attached to chain endpoint. For ex: headers: [{'X-API-Key': '...'}]  */
export function getHeaderValueFromEndpoint(endpoint: ChainEndpoint, key: string) {
  const { headers } = endpoint?.options
  const header = headers.find((val: {}) => Object.keys(val).includes(key))
  return header
}

/** returns the number of decimal places in a number (expressed as a string) - supports exponential notiation
 *  e.g. '.05' = 2, '25e-100'= 100. '2.5e-99' = 100 */
export function getDecimalPlacesFromString(num: string = '') {
  const match = num.match(/(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/)
  if (!match) {
    return 0
  }

  return Math.max(
    0,
    // Number of digits right of decimal point.
    (match[1] ? match[1].length : 0) -
      // Adjust for scientific notation.
      (match[2] ? +match[2] : 0),
  )
}

/** Converts a hex string to a unit8 byte array */
export function hexStringToByteArray(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, 'hex'))
}

/** Convert a byte array to hex string */
export function byteArrayToHexString(value: Uint8Array): string {
  return Buffer.from(value).toString('hex')
}

/** Convert a byte array to hex string */
export function bufferToHexString(value: Buffer): string {
  return value.toString('hex')
}

/** convert a decimal number string to a hex string - supports long decimals (uses BN)
 *  e.g. '16' => '0xA'  */
export function decimalToHexString(value: string) {
  return `0x${new BN(value, 10).toString('hex')}`
}

/** Return true if value is a hexidecimal encoded string (is prefixed by 0x) */
export function hasHexPrefix(value: any): boolean {
  return isAString(value) && (value as string).startsWith('0x')
}

/** Checks that string starts with 0x - appends if not
 *  Also converts hex chars to lowercase for consistency
 */
export function ensureHexPrefix(key: string) {
  if (!key) return key
  return key.startsWith('0x') ? key.toLowerCase() : `${'0x'}${key.toLowerCase()}`
}

/** Converts a decimal string to a hex string
 *  If already hex string, returns same value */
export function toHexStringIfNeeded(value: any) {
  if (!isAString(value) || value.startsWith('0x')) return value
  return decimalToHexString(value)
}

/** Whether array is exactly length of 1 */
export function isArrayLengthOne(array: any[]) {
  if (!array) return false
  return array.length === 1
}

export function objectHasProperty(obj: object, propertyName: string) {
  return Object.keys(obj).some(key => key === propertyName)
}

/** if value is empty (e.g. empty buffer), returns null, otherwise return the value passed-in */
export function nullifyIfEmpty(value: any) {
  if (isNullOrEmpty(value)) return null
  return value
}

/** Attempts to infer the precision of a token (eg ERC20) by counting digits after the decimal places in a number value string
 *  e.g. '0.120' = 3  - If no decimal places in the string, then returns default precision for token i.e. 0
 */
export function inferTokenPrecisionFromValue(value: string = ''): number {
  let decmialPlaces = getDecimalPlacesFromString(value)
  if (decmialPlaces === 0) {
    decmialPlaces = DEFAULT_TOKEN_PRECISION
  }
  return decmialPlaces
}

/** Convert a value with decimal places to a large integer string
 *  shift decimal places left by precision specified - e.g. (precision=18) ‘200.3333’ -> '200333300000000000000'
 *  base: default is base 10 (string value is a decimal number)
 *  if no precision is provided, infers precision by number of digits after decimal e.g. ‘200.3300’ = 4
 */
export function toTokenValueString(value: string, base: number = 10, precision: number): string {
  if (!isAString(value)) {
    throw new Error(
      `Token value must be string (got ${value}). Include decimal places so that converter knows how many decimals in token (e.g. '2.0000' means 4 decimals). Or, include a value for precision.`,
    )
  }
  let usePrecision = precision
  if (isNullOrEmpty(precision)) {
    usePrecision = inferTokenPrecisionFromValue(value)
  }

  // Using BigNumber library here because it supports decmials
  const bigNumber = new BigNumber(value, base)
  const result = bigNumber.shiftedBy(usePrecision)
  return result.toFixed() // no exponential notation
}

/** Convert a value shifted to have no decimal places back to include decimal places
 *  shift decimal places right by precision specified - e.g. (precision=18) '200333300000000000000' -> ‘200.3333’
 *  base: default is base 10 (string value is a decimal number)
 *  if no precision is provided, it CANT be infered from the value - so we use DEFAULT_TOKEN_PRECISION (i.e. 0)
 */
export function fromTokenValueString(value: string, base: number = 10, precision: number): string {
  let negativePrecision
  // shift decimal places to the left (negative precision value)
  if (precision) {
    negativePrecision = -1 * precision
  }
  return toTokenValueString(value, base, negativePrecision)
}

/** object is of type BN (big number) */
export function isABN(value: any) {
  return BN.isBN(value)
}

/** convert a balance and decimals into a long value string
 *  e.g. BN('200333300000000000000'), precision=18 -> '200.333' */
export function bigNumberToString(value: BN, precision: number): string {
  const bigValue = new BN(value)
  const precisionBN = new BN(precision)
  const divisor = new BN(10).pow(precisionBN)
  return `${bigValue.div(divisor)}.${bigValue.mod(divisor)}`
}

/** Convert a string with decimal places, or number or BN to a large integer string
 *  default is base 10 (string value is a decimal number) */
export function toBigIntegerString(value: string | number | BN, base: number = 10): string {
  let useValue: string | number
  // if we get a BN in, convert it to string so BigNumber can use it
  if (isABN(value)) {
    useValue = (value as BN).toString(10)
  } else if (isANumber(value)) {
    useValue = (value as number).toString(10)
  } else {
    useValue = value as string
  }
  // Using BigNumber library here because it supports decmials
  const result = new BigNumber(useValue, base)
  return result.toFixed() // no exponential notation
}
