import {
  EthereumAddress,
  EthereumTransactionAction,
  EthereumDecomposeReturn,
  EthereumChainActionType,
} from '../../../models'
import { erc20Abi } from '../../abis/erc20Abi'
import { toEthereumAddress, ethereumTrxArgIsNullOrEmpty, toBigIntegerString } from '../../../helpers'
import { getArrayIndexOrNull } from '../../../../../helpers'
import { ERC_DEFAULT_TOKEN_PRECISION } from '../../../ethConstants'

export interface Erc20TransferFromParams {
  contractAddress: EthereumAddress
  from?: EthereumAddress
  precision?: number
  transferFrom: EthereumAddress
  to: EthereumAddress
  value: string
}

export const composeAction = ({
  contractAddress,
  from,
  precision,
  transferFrom,
  to,
  value,
}: Erc20TransferFromParams) => {
  const valueBigInt = toBigIntegerString(value, 10, precision || ERC_DEFAULT_TOKEN_PRECISION)
  const contract = {
    abi: erc20Abi,
    parameters: [transferFrom, to, valueBigInt],
    method: 'transferFrom',
  }
  return {
    to: contractAddress,
    from,
    contract,
  }
}

export const decomposeAction = (action: EthereumTransactionAction): EthereumDecomposeReturn => {
  const { to, from, contract } = action
  if (contract?.abi === erc20Abi && contract?.method === 'transferFrom') {
    const returnData: Erc20TransferFromParams = {
      contractAddress: to,
      from,
      transferFrom: toEthereumAddress(getArrayIndexOrNull(contract?.parameters, 0) as string),
      to: toEthereumAddress(getArrayIndexOrNull(contract?.parameters, 1) as string),
      value: getArrayIndexOrNull(contract?.parameters, 2) as string,
    }
    const partial = !returnData?.from || ethereumTrxArgIsNullOrEmpty(to)
    return {
      chainActionType: EthereumChainActionType.ERC20TransferFrom,
      args: returnData,
      partial,
    }
  }

  return null
}
