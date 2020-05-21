import { ChainActionType } from '../../../../models'
import { EthereumAddress, EthereumTransactionAction, EthereumDecomposeReturn } from '../../models'
import { composeAction as erc20Transfer } from './erc20_transfer'

interface tokenTransferParams {
  fromAccountName?: EthereumAddress
  toAccountName?: EthereumAddress
  tokenAmount?: number
  contractName?: EthereumAddress
}

// TODO: Call erc20 transfer compose action by default instead of recreating the values here
export const composeAction = ({ fromAccountName, toAccountName, tokenAmount, contractName }: tokenTransferParams) => ({
  ...erc20Transfer({
    contractAddress: contractName,
    from: fromAccountName,
    to: toAccountName,
    value: tokenAmount,
  }),
})

export const decomposeAction = (action: EthereumTransactionAction): EthereumDecomposeReturn => {
  const { to, from, contract } = action
  if (to && from && contract && contract.method === 'transfer') {
    return {
      chainActionType: ChainActionType.TokenTransfer,
      args: { ...action },
    }
  }

  return null
}
