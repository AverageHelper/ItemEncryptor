# ItemEncryptor
A Swift package to simplify data encryption.

A Swift API for encrypting arbitrary data and data types.

I built an `Encoder` implementation based upon Swift's `Encoder` types. (Think `JSONEncoder` and `JSONSerialization`.) Any `Encodable` type can be turned into `Data`, and encrypted! Quickly and easily derive encryption keys (`EncryptionKey` objects) from user passwords, encrypt or decrypt arbitrary `Codable` types (with `EncryptionEncoder` and `EncryptionDecoder`), or do the same with arbitrary data or streams (using `EncryptionSerialization`). Keys may safely be stored and retrieved in the system Keychain using `KeychainHandle`, but the user is primarily responsible for knowing their password.

## Contributing

This project lives primarily at [git.average.name](https://git.average.name/AverageHelper/ItemEncryptor). A read-only mirror also exists on [GitHub](https://github.com/AverageHelper/ItemEncryptor). Issues or pull requests should be filed at [git.average.name](https://git.average.name/AverageHelper/ItemEncryptor). You may sign in or create an account directly, or use one of several OAuth 2.0 providers.
