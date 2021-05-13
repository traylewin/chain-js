/**
 * The PlugIn interface declares the high-level interface to create a plugin for ChainJs
 */

export enum PluginType {
  MultiSig = 'multisig',
}

export class Plugin {
  /** Plugin name */
  public name: string

  /** Plugin type */
  public type: PluginType

  /** Plugin options */
  private _options: any

  /** Chainstate - will be set automatically when plugin installed - do not set this */
  public chainState: any

  constructor(options: any) {
    this._options = options
  }

  /** Initializes plugin using options */
  init(options: any) {} // eslint-disable-line @typescript-eslint/no-unused-vars
}
