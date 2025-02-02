/* eslint-disable max-len */
/* eslint-disable import/no-unresolved */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-console */
import { ChainFactory, ChainType } from '../../../index'
import { TxExecutionPriority } from '../../../models'

import { toEthereumAddress } from '../helpers'
import {
  EthereumChainSettings,
  EthereumTransactionOptions,
  EthereumChainActionType,
  EthereumChainEndpoint,
} from '../models'
import { Erc721SafeTransferFromParams } from '../templates/chainActions/chainSpecific/erc721_safeTransferFrom'

require('dotenv').config()

const { env } = process
;(async () => {
  try {
    const rinkebyEndpoints: EthereumChainEndpoint[] = [
      {
        url: 'https://rinkeby.infura.io/v3/fc379c787fde4363b91a61a345e3620a',
        // Web3 HttpProvider options - https://github.com/ethereum/web3.js/tree/1.x/packages/web3-providers-http#usage
        // options: {
        //   timeout: 20000,
        //   headers: [{ header_name: 'header-value' }],
        // },
      },
    ]

    const rinkebyChainOptions: EthereumChainSettings = {
      chainForkType: {
        chainName: 'rinkeby',
        hardFork: 'istanbul',
      },
      defaultTransactionSettings: {
        maxFeeIncreasePercentage: 20.0,
        executionPriority: TxExecutionPriority.Fast,
      },
    }

    // EthereumRawTransaction type input for setTransaction()
    // Defaults all optional properties, so you can set from raw just with to & value OR data
    const composeERC721SafeTransferFromParams: Erc721SafeTransferFromParams = {
      contractAddress: toEthereumAddress('0xE07C99e940FA19280368E80A612EEDBB0665B68C'), // ERC721 Smart Contract Adddress
      transferFrom: toEthereumAddress('0x0F10910FA0b92a58Fcc1a5df478424D20661aDE7'), // ORE Vault Multi Sig Account
      to: toEthereumAddress('0x7eFef68B9BD9342AEC2b21681426aF541343a4dD'), // Testing MetaMask Account
      tokenId: 20,
    }

    const defaultEthTxOptions: EthereumTransactionOptions<null> = {
      chain: 'rinkeby',
      hardfork: 'istanbul',
    }

    const rinkeby = new ChainFactory().create(ChainType.EthereumV1, rinkebyEndpoints, rinkebyChainOptions)
    await rinkeby.connect()

    // ---> Sign and send erc721 transfer Transaction
    const transaction = await rinkeby.new.Transaction(rinkebyChainOptions)
    const action = await rinkeby.composeAction(
      EthereumChainActionType.ERC721SafeTransferFrom,
      composeERC721SafeTransferFromParams,
    )
    // console.log(JSON.stringify(action))
    transaction.actions = [action]
    const { contract, ...actionSentToEthChain } = transaction.actions[0]
    // extract out the transaction object sent to the eth chain
    console.log('actionSentToEthChain:', actionSentToEthChain)
    const decomposed = await rinkeby.decomposeAction(transaction.actions[0])
    console.log(decomposed)
  } catch (error) {
    console.log(error)
  }
  process.exit()
})()
