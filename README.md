# ItemEncryptor
A Swift package to simplify data encryption.

A Swift API for encrypting arbitrary data and data types.

I built an `Encoder` implementation based upon Swift's `Encoder` types. (Think `JSONEncoder` and `JSONSerialization`.) Any `Encodable` type can be turned into `Data`, and encrypted! Quickly and easily derive encryption keys (`EncryptionKey` objects) from user passwords, encrypt or decrypt arbitrary `Codable` types (with `EncryptionEncoder` and `EncryptionDecoder`), or do the same with arbitrary data or streams (using `EncryptionSerialization`). Keys may safely be stored and retrieved in the system Keychain using `KeychainHandle`, but the user is primarily responsible for knowing their password.

<!-- This is a dummy change. Please ignore -->
