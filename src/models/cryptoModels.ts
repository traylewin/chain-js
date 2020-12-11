import * as ModelsCryptoEcc from '../crypto/eccCryptoModels'
import * as ModelsCryptoEd25519 from '../crypto/ed25519CryptoModels'
import * as ModelsCryptoAsymmetric from '../crypto/asymmetricModels'

/** Brand signifiying a valid value - assigned by using toPublicKey */
enum PublicKeyBrand {
  _ = '',
}
/** Brand signifiying a valid value - assigned by using toPrivateKey */
enum PrivateKeyBrand {
  _ = '',
}
/** Brand signifiying a valid value - assigned by using toSignature */
enum SignatureBrand {
  _ = '',
}
/** Brand signifiying a valid value - assigned by using toEncryptedDataString */
enum EncryptedDataStringBrand {
  _ = '',
}

/** Stringified JSON ciphertext (used for private keys) */
type EncryptedDataString = string & EncryptedDataStringBrand
/** a public key string - formatted correctly for the chain */
// TODO: eth public key is of type buffer
type PublicKey = (string & PublicKeyBrand) | any
/** a private key string - formatted correctly for the chain */
type PrivateKey = (string & PrivateKeyBrand) | any
/** a signature string - formatted correcly for the chain */
type Signature = string & SignatureBrand

type KeyPair = {
  publicKey: PublicKey
  privateKey: PrivateKey
}

type KeyPairEncrypted = {
  public: PublicKey
  privateEncrypted: EncryptedDataString
}

type AccountKeysStruct = {
  publicKeys: {
    active: PublicKey
  }
  privateKeys: {
    active: PrivateKey | EncryptedDataString
  }
}

enum CryptoCurve {
  Secp256k1 = 'secp256k1',
  Ed25519 = 'ed25519',
}

// exporting explicity in order to alias Models.. exports
export {
  AccountKeysStruct,
  CryptoCurve,
  EncryptedDataStringBrand,
  EncryptedDataString,
  KeyPair,
  KeyPairEncrypted,
  ModelsCryptoEcc,
  ModelsCryptoEd25519,
  ModelsCryptoAsymmetric,
  PrivateKey,
  PrivateKeyBrand,
  PublicKey,
  PublicKeyBrand,
  Signature,
  SignatureBrand,
}
