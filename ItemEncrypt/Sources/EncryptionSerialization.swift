//
//  API.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto


// MARK: - EncryptionSerialization

/// `EncryptionSerialization` is a helper interface to securely encrypt raw data blocks.
///  Use `EncryptionEncoder` to encrypt semantic data types.
public enum EncryptionSerialization {
    // MARK: Options
    
    public enum EncryptionError: Error {
        case noPassword
    }
    
    public enum DecryptionError: Error {
        case badData
        case incorrectVersion
        case noPassword
    }
    
    // MARK: - Key Derivation
    
    /// Returns an array of cryptographically random data of the given length.
    public static func randomBytes(count: Int) -> [UInt8] {
        return try! Random.generateBytes(byteCount: count)
    }
    
    /// Derives a key using PBKDF2 from the given password using the given encryption scheme.
    public static func deriveKey(password: String, salt: [UInt8], scheme: EncryptionSerialization.Scheme) -> [UInt8] {
        return PBKDF.deriveKey(password: password,
                                  salt: salt,
                                  prf: scheme.randomAlgorithm,
                                  rounds: scheme.iterations,
                                  derivedKeyLength: scheme.derivedKeyLength.rawValue)
    }
    
    // MARK: - Encryption
    
    /// Performs SHA256 encryption on `data`, using a key generated from `password`.
    ///
    /// A key should be generated using PBKDF2 and a cryptographically random salt, which is
    ///   attached to the returned object for later use.
    ///
    /// - parameter data: A data block to be encrypted.
    /// - parameter password: The password by which to encrypt the data. This must
    ///     not be empty.
    /// - parameter scheme: The set of configuration options to use when encrypting the data.
    /// - returns: An `EncryptedItem` representing the encrypted data.
    public static func encryptedItem(with data: Data, password: String, scheme: Scheme) throws -> EncryptedItem {
        
        guard !password.isEmpty else {
            throw EncryptionError.noPassword
        }
        
        let seed = randomBytes(count: scheme.seedSize)
        let iv = randomBytes(count: scheme.initializationVectorSize)
        let derivedKey = EncryptionKey(untreatedPassword: password,
                                       seed: seed,
                                       iv: iv,
                                       scheme: scheme)
        
        return encryptedItem(with: data, key: derivedKey)
    }
    
    /// Performs SHA256 encryption on `data`, using the given encryption `key`.
    ///
    /// - parameter data: A data block to be encrypted.
    /// - parameter key: The key to use for encryption.
    /// - returns: An `EncryptedItem` representing the encrypted data.
    public static func encryptedItem(with data: Data, key: EncryptionKey) -> EncryptedItem {
        
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
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        let encryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        return EncryptedItem(version: scheme.version, payload: encryptedData, salt: salt, iv: iv)
    }
    
    /// Encrypts data from an input stream, sending output data to another stream.
    ///
    /// Encrypts data from an input stream, sending output data to another stream. This output may be shunted into an `EncryptedItem` payload, or used in any other way.
    ///
    /// - parameter input: The input data stream.
    /// - parameter key: The key with which to encrypt the data.
    /// - parameter output: A stream of encrypted data.
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
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: input, outputStream: output, bufferSize: scheme.bufferSize)
    }
    
    // MARK: - Decryption
    
    /// Attempts to decrypt the given `object` using a key derived from the given `password`.
    public static func data(withEncryptedObject object: EncryptedItem, password: String) throws -> Data {
        
        guard !password.isEmpty else {
            throw DecryptionError.noPassword
        }
        
        let derivedKey = EncryptionKey(untreatedPassword: password,
                                       treatedSalt: object.salt,
                                       iv: object.iv,
                                       scheme: Scheme(format: object.version))
        return try data(withEncryptedObject: object, key: derivedKey)
    }
    
    /// Attempts to decrypt the given `object` using the given `key`.
    public static func data(withEncryptedObject object: EncryptedItem, key: EncryptionKey) throws -> Data {
        
        let scheme = Scheme(format: object.version)
        guard scheme == key.scheme else {
            throw DecryptionError.incorrectVersion
        }
        
        let data = object.payload
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
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        let decryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        return decryptedData
    }
    
    /// Decrypts data from an input stream, sending output data to another stream.
    ///
    /// Decrypts data from an input stream, sending output data to another stream. The input may be the payload of an `EncryptedItem`, or from something else.
    ///
    /// - parameter input: A stream of encrypted data.
    /// - parameter key: The key with which to decrypt the data.
    /// - parameter output: A stream of the decrypted data.
    public static func decryptDataStream(_ input: InputStream, withKey key: EncryptionKey, into output: OutputStream) {
        
        let scheme = key.scheme
        let keyData = key.keyData
        let iv = key.initializationVector
        
        let cryptor = StreamCryptor(operation: .decrypt,
                                    algorithm: scheme.encryptionAlgorithm,
                                    mode: scheme.algorithmMode,
                                    padding: .PKCS7Padding,
                                    key: keyData,
                                    iv: iv)
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: input, outputStream: output, bufferSize: scheme.bufferSize)
    }
    
    // MARK: - The actual encryption.
    
    /// Uses the IDZSwiftSerialization library to encrypt or decrypt the given data stream.
    private static func crypt(sc: StreamCryptor, inputStream: InputStream, outputStream: OutputStream, bufferSize: Int) {
        
        var inputBuffer = [UInt8](repeating: 0, count: bufferSize)
        var outputBuffer = [UInt8](repeating: 0, count: bufferSize)
        inputStream.open()
        outputStream.open()
        
        var cryptedBytes = 0
        while inputStream.hasBytesAvailable {
            
            let bytesRead = inputStream.read(&inputBuffer, maxLength: inputBuffer.count)
            let status = sc.update(bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
            assert(status == Status.success)
            
            if cryptedBytes > 0 {
                let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
                assert(bytesWritten == Int(cryptedBytes))
            }
        }
        
        let status = sc.final(bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &cryptedBytes)
        assert(status == Status.success)
        
        if cryptedBytes > 0 {
            let bytesWritten = outputStream.write(outputBuffer, maxLength: Int(cryptedBytes))
            assert(bytesWritten == Int(cryptedBytes))
        }
        
        inputStream.close()
        outputStream.close()
    }
    
}
