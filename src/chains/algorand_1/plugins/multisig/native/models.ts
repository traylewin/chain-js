import { AlgorandAddress } from '../../../models'

export type AlgorandNativeMultisigOptions = {
  version: number
  threshold: number
  addrs: AlgorandAddress[]
}
