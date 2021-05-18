import * as algosdk from 'algosdk'
import { isNullOrEmpty } from '../../../../../helpers'
import { AlgorandMultiSigAccount } from '../../../models'
import { AlgorandNativeMultisigOptions } from './models'

/** Calculates the multisig address using the multisig options including version, threshhold and addresses */
export function determineMultiSigAddress(multisigOptions: AlgorandNativeMultisigOptions): AlgorandMultiSigAccount {
  if (isNullOrEmpty(multisigOptions)) return null
  return algosdk.multisigAddress(multisigOptions)
}
