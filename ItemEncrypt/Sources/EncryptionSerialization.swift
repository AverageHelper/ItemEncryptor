//
//  API.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto
import CryptoKit


// MARK: - EncryptionSerialization

/// An interface for securely encrypting raw data blocks.
///
/// Use `EncryptionEncoder` and `EncryptionDecoder` to encrypt and decrypt semantic data
/// types, respectively.
public enum EncryptionSerialization {
    // MARK: Options
    
    /// An error indicating an issue encrypting data.
    public enum EncryptionError: Error {
        /// No password was provided (either `nil` or an empty string).
        case noPassword
    }
    
    /// An error indicating an issue decrypting data.
    public enum DecryptionError: Error {
        /// The data was malformatted.
        case badData
        
        /// An encryption attempt was made using a different encryption scheme than was used
        /// to encrypt the data.
        case incorrectVersion
        
        /// No password was provided (either `nil` or an empty string).
        case noPassword
    }
    
    // MARK: - Key Derivation
    
    /// Returns an array of cryptographically random data of the given length.
    ///
    /// - parameter count: The number of bytes the resulting data block should contain.
    /// - returns: An array of cryptographically random bytes (`UInt8` values).
    public static func randomBytes(count: Int) -> [UInt8] {
        return try! Random.generateBytes(byteCount: count)
    }
    
    /// Derives a key using PBKDF2 from the given password using the given encryption scheme.
    ///
    /// - parameter password: A password string used to derive the key.
    /// - parameter salt: Some data used to add to the "randomness" of the returned key data.
    /// - parameter scheme: A value that determines the randomization function and number of
    ///     rounds used, as well as the key length.
    ///
    /// - returns: A block of data which may be used as an encryption key.
    public static func keyData(from password: String,
                               salt: EncryptedItem.Salt,
                               using scheme: Scheme) -> EncryptionKey.KeyData {
        
        return PBKDF.deriveKey(password: password,
                               salt: salt,
                               prf: scheme.randomAlgorithm,
                               rounds: scheme.iterations,
                               derivedKeyLength: scheme.derivedKeyLength.rawValue)
    }
    
    @available(*, deprecated, renamed: "keyData(from:salt:using:)")
    public static func deriveKey(password: String,
                                 salt: EncryptedItem.Salt,
                                 scheme: Scheme) -> EncryptionKey.KeyData {
        return keyData(from: password, salt: salt, using: scheme)
    }
    
    // MARK: - Encryption
    
    /// Performs encryption on `data` based on the algorithm defined in `scheme`, using a
    /// new random key derived from `password`.
    ///
    /// The key will be generated using PBKDF2 and a cryptographically random salt, which is
    /// attached to the returned object for later use.
    ///
    /// - parameter data: A data block to be encrypted.
    /// - parameter password: The password from which a new random key is derived. This key
    ///     is used to encrypt the given `value`. This password is not retained past the
    ///     lifetime of the function call.
    /// - parameter scheme: The set of configuration options to use when encrypting the data.
    ///
    /// - returns: An `EncryptedItem` representing the encrypted data.
    public static func encryptedItem(with data: Data, password: String, scheme: Scheme) throws -> EncryptedItem {
        
        guard !password.isEmpty else {
            throw EncryptionError.noPassword
        }
        
        let seed = randomBytes(count: scheme.seedSize)
        let iv = randomBytes(count: scheme.initializationVectorSize)
        let derivedKey = try! EncryptionKey(untreatedPassword: password,
                                            seed: seed,
                                            iv: iv,
                                            scheme: scheme)
        
        return encryptedItem(with: data, key: derivedKey)
    }
    
    /// Performs encryption on `data` using the given encryption `key`.
    ///
    /// - parameter data: A data block to be encrypted.
    /// - parameter key: The key to use for encryption.
    ///
    /// - returns: An `EncryptedItem` representing the encrypted data.
    public static func encryptedItem(with data: Data, key: EncryptionKey) -> EncryptedItem {
        
        switch key.scheme.version {
        case .version1: // Use IDZSwiftCommonCrypto
            let scheme = key.scheme
            let keyData = key.keyData
            let iv = key.initializationVector
            let salt = key.salt
            
            let cryptor = StreamCryptor(operation: .encrypt,
                                        algorithm: scheme.encryptionAlgorithm,
                                        mode: scheme.algorithmMode,
                                        padding: .PKCS7Padding,
                                        key: keyData,
                                        iv: iv)
            
            let dataStream = InputStream(data: data)
            let outStream = OutputStream(toMemory: ())
            let bufferSize = scheme.bufferSize
            
            EncryptionSerialization.crypt(using: cryptor,
                                          inputStream: dataStream,
                                          outputStream: outStream,
                                          bufferSize: bufferSize)
            
            let encryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
            
            return EncryptedItem(version: scheme.version,
                                 payload: encryptedData,
                                 salt: salt,
                                 iv: iv)
            
        case .version2: // Use CryptoKit
            guard #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) else {
                fatalError("SANITY ERROR: version2 should only be accessible on newer OS versions.")
            }
            let symmetricKey = SymmetricKey(data: key.keyData)
            let sealedBox = try! ChaChaPoly.seal(data, using: symmetricKey)
            return try! EncryptedItem(sealedBox)
        }
    }
    
    /// Encrypts data from an input stream, sending output data to another stream.
    ///
    /// Encrypts data from an input stream, sending output data to another stream. This
    /// output may be shunted into an `EncryptedItem` payload, or used in any other way.
    ///
    /// - parameter input: The input data stream.
    /// - parameter key: The key with which to encrypt the data.
    /// - parameter output: A stream of encrypted data.
    @available(iOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(OSX, deprecated: 10.15, message: "Stream operations are not supported in data package version 2.")
    @available(watchOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(tvOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(*, deprecated, message: "Stream operations are not supported in data package version 2.")
    public static func encryptDataStream(_ input: InputStream, withKey key: EncryptionKey, into output: OutputStream) {
        
        let scheme = key.scheme
        let keyData = key.keyData
        let iv = key.initializationVector
        
        let cryptor = StreamCryptor(operation: .encrypt,
                                    algorithm: scheme.encryptionAlgorithm,
                                    mode: scheme.algorithmMode,
                                    padding: .PKCS7Padding,
                                    key: keyData,
                                    iv: iv)
        
        EncryptionSerialization.crypt(using: cryptor, inputStream: input, outputStream: output, bufferSize: scheme.bufferSize)
    }
    
    // MARK: - Decryption
    
    /// Attempts to decrypt the given `object` using a key derived from the given `password`.
    ///
    /// - parameter object: A semantic representation of encrypted data to be decrypted.
    /// - parameter password: The password with which the data was encrypted. This must
    ///     not be empty.
    ///
    /// - throws: A `DecryptionError` if the decryption fails.
    /// - returns: The decrypted `Data`.
    public static func data(fromEncryptedObject object: EncryptedItem,
                            password: String) throws -> Data {
        
        guard !password.isEmpty else {
            throw DecryptionError.noPassword
        }
        
        let derivedKey = try EncryptionKey(untreatedPassword: password,
                                           treatedSalt: object.salt,
                                           iv: object.iv,
                                           scheme: Scheme(format: object.version))
        return try data(fromEncryptedObject: object, key: derivedKey)
    }
    
    @available(*, deprecated, renamed: "data(fromEncryptedObject:password:)")
    public static func data(withEncryptedObject object: EncryptedItem, password: String) throws -> Data {
        return try data(fromEncryptedObject: object, password: password)
    }
    
    /// Attempts to decrypt the given `object` using the given `key`.
    ///
    /// - parameter object: A semantic representation of encrypted data to be decrypted.
    /// - parameter key: The key with which the data was encrypted.
    ///
    /// - throws: A `DecryptionError` if the decryption fails.
    /// - returns: The decrypted `Data`.
    public static func data(fromEncryptedObject object: EncryptedItem,
                            key: EncryptionKey) throws -> Data {
        
        switch object.version {
        case .version1: // Use IDZSwiftCommonCrypto
            let scheme = Scheme(format: object.version)
            
            let data = object.ciphertext
            let iv = key.initializationVector
            let keyData = key.keyData
            
            let cryptor = StreamCryptor(operation: .decrypt,
                                        algorithm: scheme.encryptionAlgorithm,
                                        mode: scheme.algorithmMode,
                                        padding: .PKCS7Padding,
                                        key: keyData,
                                        iv: iv)
            
            let dataStream = InputStream(data: data)
            let outStream = OutputStream(toMemory: ())
            let bufferSize = scheme.bufferSize
            
            EncryptionSerialization.crypt(using: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
            
            let decryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
            
            return decryptedData
            
        case .version2: // Use CryptoKit
            guard #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) else {
                fatalError("SANITY ERROR: version2 should only be accessible on newer OS versions.")
            }
            do {
                let sealedBox = try ChaChaPoly.SealedBox(object)
                let symmetricKey = SymmetricKey(data: key.keyData)
                return try ChaChaPoly.open(sealedBox, using: symmetricKey)
                
            } catch {
                throw DecryptionError.badData
            }
        }
    }
    
    @available(*, deprecated, renamed: "data(fromEncryptedObject:key:)")
    public static func data(withEncryptedObject object: EncryptedItem,
                            key: EncryptionKey) throws -> Data {
        return try data(fromEncryptedObject: object, key: key)
    }
    
    /// Decrypts data from an input stream, sending output data to another stream.
    ///
    /// Decrypts data from an input stream, sending output data to another stream. The input may be the payload of an `EncryptedItem`, or from something else.
    ///
    /// - parameter input: A stream of encrypted data.
    /// - parameter key: The key with which to decrypt the data.
    /// - parameter output: A stream of the decrypted data.
    @available(iOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(OSX, deprecated: 10.15, message: "Stream operations are not supported in data package version 2.")
    @available(watchOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(tvOS, deprecated: 13.0, message: "Stream operations are not supported in data package version 2.")
    @available(*, deprecated, message: "Stream operations are not supported in data package version 2.")
    public static func decryptDataStream(_ input: InputStream,
                                         withKey key: EncryptionKey,
                                         into output: OutputStream) {
        
        let scheme = key.scheme
        let keyData = key.keyData
        let iv = key.initializationVector
        
        let cryptor = StreamCryptor(operation: .decrypt,
                                    algorithm: scheme.encryptionAlgorithm,
                                    mode: scheme.algorithmMode,
                                    padding: .PKCS7Padding,
                                    key: keyData,
                                    iv: iv)
        
        EncryptionSerialization.crypt(using: cryptor, inputStream: input, outputStream: output, bufferSize: scheme.bufferSize)
    }
    
    // MARK: - The actual encryption.
    
    /// Uses the IDZSwiftSerialization library to encrypt or decrypt the given data stream.
    private static func crypt(using cryptor: StreamCryptor,
                              inputStream: InputStream,
                              outputStream: OutputStream,
                              bufferSize: Int) {
        
        var inputBuffer = [UInt8](repeating: 0, count: bufferSize)
        var outputBuffer = [UInt8](repeating: 0, count: bufferSize)
        inputStream.open()
        outputStream.open()
        
        var cryptedBytes = 0
        while inputStream.hasBytesAvailable {
            
            let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)
            let status = cryptor.update(bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
            precondition(status == Status.success)
            
            if cryptedBytes > 0 {
                let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
                precondition(bytesWritten == Int(cryptedBytes))
            }
        }
        
        let status = cryptor.final(bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
        precondition(status == Status.success)
        
        if cryptedBytes > 0 {
            let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
            precondition(bytesWritten == Int(cryptedBytes))
        }
        
        inputStream.close()
        outputStream.close()
    }
    
}
