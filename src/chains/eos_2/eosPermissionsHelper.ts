/* eslint-disable @typescript-eslint/naming-convention */
/* eslint-disable no-restricted-syntax */
import {
  EosEntityName,
  EosPermissionStruct,
  EosPublicKey,
  EosActionStruct,
  EosPermissionSimplified,
  EosNewKeysOptions,
  EosGeneratedPermissionKeys,
  DeletePermissionsParams,
  ReplacePermissionKeysParams,
  LinkPermissionsParams,
  UnlinkPermissionsParams,
  EosPermission,
  EosRequiredAuthorization,
} from './models'
import { EosChainState } from './eosChainState'
import { composeAction } from './eosCompose'
import { throwNewError } from '../../errors'
import { generateKeyPairAndEncryptPrivateKeys } from './eosCrypto'
import { isNullOrEmpty } from '../../helpers'
import { toEosEntityName } from './helpers'
import { ChainActionType } from '../../models'

export class PermissionsHelper {
  private _chainState: EosChainState

  constructor(chainState: EosChainState) {
    this._chainState = chainState
  }

  // permissions

  /** return a fully formed EOS permission structure (EosPermissionStruct) */
  composePermission(
    publicKeys: EosPublicKey[],
    permissionName: EosEntityName,
    parentPermissionName: EosEntityName | '',
    threshold: number = 1,
    weight: number = 1,
  ): EosPermissionStruct {
    const permission: EosPermissionStruct = {
      parent: parentPermissionName,
      perm_name: permissionName,
      required_auth: {
        accounts: [],
        keys: this.weightPermissionKeys(publicKeys, weight),
        threshold,
        waits: [],
      },
    }

    return permission
  }

  weightPermissionKeys = (keys: EosPublicKey[], weight = 1): { key: EosPublicKey; weight: number }[] => {
    return keys.map(key => ({ key, weight }))
  }

  // TODO: Allow more than one public key to be passed-in to be added to required_auth
  // Currently only using the public key for the permission

  /** Compose a collection of actions to add the requested permissions */
  async composeAddPermissionActions(
    authAccount: EosEntityName,
    authPermission: EosEntityName,
    permissionsToAdd: Partial<EosPermissionSimplified>[] = [],
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    appendKeyToExistingPermission: boolean = false,
  ): Promise<EosActionStruct[]> {
    if (isNullOrEmpty(permissionsToAdd)) return null
    const updateAuthActions: EosActionStruct[] = []

    // tell Typescript that permissionsToAdd is now always EosPermissionSimplified[]
    const usePermissionsToAdd = permissionsToAdd as EosPermissionSimplified[]

    const newPermissions: EosPermissionStruct[] = []
    // TODO: if appendKeyToExistingPermission = true, add the new key to the existing permission's require_auth array
    // collect an array of new permission objects
    usePermissionsToAdd.forEach(p => {
      const parent = p.name === toEosEntityName('owner') && isNullOrEmpty(p.parent) ? '' : toEosEntityName(p.parent)
      const permissionToAdd = this.composePermission(
        [p.publicKey],
        toEosEntityName(p.name),
        parent,
        p.threshold,
        p.publicKeyWeight,
      )
      newPermissions.push(permissionToAdd)
    })
    // compose updateAuth actions
    // Todo: Sort newPermissions by dependencies in case one permission to add requires another one in the list as its parent
    newPermissions.map(async permissionToAdd => {
      const updateAuthParams = {
        auth: permissionToAdd.required_auth,
        authAccount,
        authPermission,
        parent: permissionToAdd.parent,
        permission: permissionToAdd.perm_name,
      }
      const updateAuthAction = await composeAction(ChainActionType.AccountUpdateAuth, updateAuthParams)
      updateAuthActions.push(updateAuthAction)
    })

    return updateAuthActions
  }

  composeDeletePermissionActions = async (
    authAccount: EosEntityName,
    authPermission: EosEntityName,
    permissionsToDelete: DeletePermissionsParams[] = [],
  ): Promise<EosActionStruct[]> => {
    const delteAuthActions: EosActionStruct[] = []
    if (isNullOrEmpty(permissionsToDelete)) return null

    permissionsToDelete.map(async auth => {
      const deleteAuthParams = {
        authAccount,
        authPermission,
        account: auth.accountName,
        permission: auth.permissionName,
      }
      const deleteAuthAction = await composeAction(ChainActionType.AccountDeleteAuth, deleteAuthParams)
      delteAuthActions.push(deleteAuthAction)
    })

    return delteAuthActions
  }

  /** Compose an action to replace public keys on an existing account permission */
  composeReplacePermissionKeysAction = async (
    authAccount: EosEntityName,
    authPermission: EosEntityName,
    params: ReplacePermissionKeysParams,
  ): Promise<EosActionStruct> => {
    const { permissionName, parentPermissionName, publicKeys, accountName, accountPermissions } = params
    if (isNullOrEmpty(accountPermissions)) return null

    const permission = accountPermissions.find(p => p.name === permissionName)
    if (!permission)
      throwNewError(
        `composeReplacePermissionKeysAction: Specified account ${accountName} doesn't have a permission name ${permissionName}`,
      )
    // TODO: Unlink all permissions under the permission being replaced
    // ... otherwise RAM will be orphaned on-chain for those permisisons linked to actions
    const permissionToUpdate = this.composePermission(
      publicKeys,
      toEosEntityName(permissionName),
      toEosEntityName(parentPermissionName),
    )

    // compose the updateAuth action
    const updateAuthParams = {
      auth: permissionToUpdate.required_auth,
      authAccount: accountName,
      authPermission: 'owner',
      parent: permissionToUpdate.parent,
      permission: permissionToUpdate.perm_name,
    }
    const updateAuthAction = await composeAction(ChainActionType.AccountUpdateAuth, updateAuthParams)
    return updateAuthAction
  }

  /** Compose a collection of actions to link actions to permissions */
  composeLinkPermissionActions = async (
    authAccount: EosEntityName,
    authPermission: EosEntityName,
    permissionsToLink: LinkPermissionsParams[] = [],
  ): Promise<EosActionStruct[]> => {
    const linkAuthActions: EosActionStruct[] = []
    if (isNullOrEmpty(permissionsToLink)) return null

    permissionsToLink.map(async link => {
      const linkAuthParams = {
        authAccount,
        authPermission,
        contract: link.contract,
        action: link.action,
        permission: link.permissionName,
      }
      const linkAuthAction = await composeAction(ChainActionType.AccountLinkAuth, linkAuthParams)
      linkAuthActions.push(linkAuthAction)
    })

    return linkAuthActions
  }

  /** Compose a collection of actions to unlink actions to permissions */
  composeUnlinkPermissionActions = async (
    authAccount: EosEntityName,
    authPermission: EosEntityName,
    permissionsToUnlink: UnlinkPermissionsParams[] = [],
  ): Promise<EosActionStruct[]> => {
    if (isNullOrEmpty(permissionsToUnlink)) return null
    const unlinkAuthActions: EosActionStruct[] = []

    permissionsToUnlink.map(async link => {
      const unlinkAuthParams = {
        action: link.action,
        authAccount,
        authPermission,
        contract: link.contract,
      }
      const unlinkAuthAction = await composeAction(ChainActionType.AccountUnlinkAuth, unlinkAuthParams)
      unlinkAuthActions.push(unlinkAuthAction)
    })

    return unlinkAuthActions
  }

  // TODO: Optimize this algorithm

  /** Iterates over the permissions array.
   * Maps permissions by name, and populates its children
   * Returns the deepest permission in the tree, starting from the root permission node */
  findDeepestPermission = (permissions: EosPermissionStruct[], rootPermission: EosEntityName): EosPermissionStruct => {
    // First, construct the mapping, from the array...
    const permMap: any[] = [] // Maps the permissions by name (Contructs the tree)
    for (const perm of permissions as any) {
      permMap[perm.perm_name] = perm // Set the permission in the mapping/tree
      perm.children = [] // Set an empty children array, in prep for population in the next iteration
    }
    // Then, fill in the tree, with children...
    for (const perm of permissions as any) {
      const parent = permMap[perm.parent]
      if (parent) {
        parent.children.push(perm)
      }
    }
    // Finally, find the deepest child, with BFS...
    const root = permMap[rootPermission as any]
    let nodesInLevel = [root]
    let deepest = root
    let depth = 0
    while (nodesInLevel.length > 0) {
      let nextLevel: any[] = []
      for (const node of nodesInLevel) {
        node.depth = depth
        deepest = node
        nextLevel = nextLevel.concat(node.children)
      }
      nodesInLevel = nextLevel
      depth += 1
    }
    return deepest as EosPermissionStruct
  }

  /** generate a keypair for any new permissions missing a public key */
  static generateMissingKeysForPermissionsToAdd = async (
    permissionsToAdd: Partial<EosPermissionSimplified>[],
    newKeysOptions: EosNewKeysOptions,
  ) => {
    const generatedKeys: EosGeneratedPermissionKeys[] = []
    const { password, encryptionOptions } = newKeysOptions || {}

    if (isNullOrEmpty(permissionsToAdd)) {
      return null
    }

    // add public kets to existing permissionsToAdd parameter
    const keysToFix = permissionsToAdd.map(async p => {
      if (!p.publicKey) {
        const updatedPerm = p
        const keys = await generateKeyPairAndEncryptPrivateKeys(password, encryptionOptions)
        updatedPerm.publicKey = keys.publicKey
        updatedPerm.publicKeyWeight = 1
        generatedKeys.push({ permissionName: updatedPerm.name, keyPair: keys })
      }
    })
    await Promise.all(keysToFix)
    return { generatedKeys, permissionsToAdd }
  }

  /** Convert raw account permissions strucutre to EOSPermission */
  static mapPermissionStructToEosPermission = (accountPermissionStruct: EosPermissionStruct): EosPermission => {
    const { parent, perm_name: name, required_auth } = accountPermissionStruct
    if (isNullOrEmpty(required_auth)) return null

    const requiredAuth: EosRequiredAuthorization = {
      ...required_auth,
      // only field that needs to change is to rename camel case wait_sec
      waits: required_auth.waits.map(w => ({ waitSec: w.wait_sec, weight: w.weight })),
    }
    const { threshold, keys } = requiredAuth
    const { key: firstPublicKey, weight: firstPublicWeight } = keys[0] || {}
    const firstPublicKeyMeetsThreshold = firstPublicWeight >= threshold
    const eosPermission = { firstPublicKey, firstPublicKeyMeetsThreshold, name, parent, requiredAuth }

    return eosPermission
  }
}
