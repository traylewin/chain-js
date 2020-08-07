// How to use fetch mocks - https://www.npmjs.com/package/jest-fetch-mock
import { composeAction } from '../algoCompose'
import { decomposeAction } from '../algoDecompose'
import {
  AlgorandChainActionType,
  AlgorandActionAssetCreateParams,
  AlgorandActionAssetConfigParams,
  AlgorandActionAssetFreezeParams,
  AlgorandActionAssetTransferParams,
  AlgorandActionAssetDestroyParams,
  AlgorandKeyRegistrationParams,
  AlgorandActionPaymentParams,
} from '../models'
import { getChainState } from './mockups/chainState'
import {
  decomposedAssetCreate,
  decomposedAssetConfig,
  decomposedAssetFreeze,
  decomposedAssetTransfer,
  decomposedAssetDestroy,
  decomposedKeyRegistration,
  decomposedPayment,
} from './mockups/decomposedActions'

// import { AlgorandChainState } from '../algoChainState'

describe('Compose Algorand Chain Actions', () => {
  it('creates asset create action object', async () => {
    const args: AlgorandActionAssetCreateParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      totalIssuance: 1000,
      assetDefaultFrozen: false,
      assetDecimals: 0,
      assetReserve: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetFreeze: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetClawback: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetManager: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetUnitName: 'exp',
      assetName: 'examplecoin',
      assetURL: '',
      assetMetadataHash: '',
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.AssetCreate, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedAssetCreate)
  })

  it('creates asset config action object', async () => {
    const args: AlgorandActionAssetConfigParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      assetIndex: 12345,
      assetReserve: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetFreeze: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetClawback: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetManager: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      strictEmptyAddressChecking: false,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.AssetConfig, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedAssetConfig)
  })

  it('creates asset freeze action object', async () => {
    const args: AlgorandActionAssetFreezeParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      assetIndex: 12345,
      freezeTarget: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      freezeState: true,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.AssetFreeze, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedAssetFreeze)
  })

  it('creates asset transfer action object', async () => {
    const args: AlgorandActionAssetTransferParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      to: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      assetIndex: 12345,
      closeRemainderTo: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      assetRevocationTarget: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      amount: 1000,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.AssetTransfer, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedAssetTransfer)
  })

  it('creates asset destroy action object', async () => {
    const args: AlgorandActionAssetDestroyParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      assetIndex: 12345,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.AssetDestroy, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedAssetDestroy)
  })

  it('creates key registration action object', async () => {
    const args: AlgorandKeyRegistrationParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      voteKey: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      selectionKey: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      voteFirst: 10,
      voteLast: 100000,
      voteKeyDilution: 100,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.KeyRegistration, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedKeyRegistration)
  })

  it('creates payment action object', async () => {
    const args: AlgorandActionPaymentParams = {
      from: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      note: 'create',
      to: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      closeRemainderTo: 'VBS2IRDUN2E7FJGYEKQXUAQX3XWL6UNBJZZJHB7CJDMWHUKXAGSHU5NXNQ',
      amount: 10,
    }
    const chainState = await getChainState()
    const composedAction = await composeAction(chainState, AlgorandChainActionType.Payment, args)

    const actAction = decomposeAction(composedAction)

    expect(actAction).toEqual(decomposedPayment)
  })
})
