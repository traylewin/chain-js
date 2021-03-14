import * as algosdk from 'algosdk'
import {
  AlgorandActionAppMultiPurpose,
  AlgorandDecomposeReturn,
  AlgorandChainActionType,
  AlgorandSuggestedParams,
  AlgorandTransactionTypeCode,
  AlgorandTxAction,
  AlgorandTxActionRaw,
  AlgorandOnApplicationComplete,
} from '../../../models'
import { AlgorandActionHelper } from '../../../algoAction'
import { isNullOrEmpty } from '../../../../../helpers'

/** Composes a transaction that clears a user's state in an application */
export const composeAction = async (args: AlgorandActionAppMultiPurpose, suggestedParams: AlgorandSuggestedParams) => {
  const argsEncodedForSdk = new AlgorandActionHelper(args as AlgorandTxAction).actionEncodedForSdk
  const {
    from,
    appIndex,
    appArgs,
    appAccounts,
    appForeignApps,
    appForeignAssets,
    note,
    lease,
    reKeyTo,
  } = argsEncodedForSdk
  const composedAction = algosdk.makeApplicationClearStateTxn(
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
    actionParams?.appOnComplete === AlgorandOnApplicationComplete.Clear &&
    !(actionParams?.appIndex === 0 || !actionParams?.appIndex)
  ) {
    const returnData = {
      ...actionParams,
    }
    return {
      chainActionType: AlgorandChainActionType.AppClear,
      args: returnData,
    }
  }
  return null
}
