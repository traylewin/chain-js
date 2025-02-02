import * as algosdk from 'algosdk'
import {
  AlgorandActionAppMultiPurposeParams,
  AlgorandDecomposeReturn,
  AlgorandChainActionType,
  AlgorandSuggestedParams,
  AlgorandTransactionTypeCode,
  AlgorandTxAction,
  AlgorandTxActionRaw,
} from '../../../models'
import { AlgorandActionHelper } from '../../../algoAction'
import { isNullOrEmpty } from '../../../../../helpers'

/** Composes a transaction that opts in to use an application */
export const composeAction = async (
  args: AlgorandActionAppMultiPurposeParams,
  suggestedParams: AlgorandSuggestedParams,
) => {
  const argsEncodedForSdk = new AlgorandActionHelper(args as AlgorandTxAction).actionEncodedForSdk
  const { from, appIndex, appArgs, appAccounts, appForeignApps, appForeignAssets, note, lease, reKeyTo } =
    argsEncodedForSdk
  const composedAction = algosdk.makeApplicationCloseOutTxn(
    from,
    suggestedParams,
    appIndex,
    appArgs,
    appAccounts,
    appForeignApps,
    appForeignAssets,
    note,
    lease,
  )
  if (!isNullOrEmpty(reKeyTo)) {
    composedAction.addRekey(reKeyTo)
  }
  const actionHelper = new AlgorandActionHelper(composedAction)
  return actionHelper.action // convert raw action to use hex strings
}

export const decomposeAction = (action: AlgorandTxAction | AlgorandTxActionRaw): AlgorandDecomposeReturn => {
  const actionHelper = new AlgorandActionHelper(action)
  const actionParams = actionHelper.paramsOnly
  // Cant identify using only type (more than one action uses Application type) - must check params too
  if (
    actionParams?.type === AlgorandTransactionTypeCode.Application &&
    actionParams?.appOnComplete === algosdk.OnApplicationComplete.CloseOutOC &&
    !(actionParams?.appIndex === 0 || !actionParams?.appIndex)
  ) {
    const returnData = {
      ...actionParams,
    }
    return {
      chainActionType: AlgorandChainActionType.AppCloseOut,
      args: returnData,
    }
  }
  return null
}
