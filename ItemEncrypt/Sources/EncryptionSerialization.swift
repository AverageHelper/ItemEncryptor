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
    
    public enum DecryptionError: Error {
        case badData
        case incorrectVersion
    }
    
    // MARK: - Key Derivation
    
    /// Derives a key using PBKDF2 from the given password using the given encryption scheme.
    public static func keyFromPassword(_ password: String, salt: [UInt8], scheme: EncryptionSerialization.Scheme) -> [UInt8] {
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
    public static func encryptedItem(with data: Data, password: String, scheme: Scheme) -> EncryptedItem {
        
        guard !password.isEmpty else {
            fatalError("Password was found empty.")
        }
        
        let salt = try! Random.generateBytes(byteCount: scheme.saltSize)
        let key = EncryptionSerialization.keyFromPassword(password, salt: salt, scheme: scheme)
        
        guard !key.isEmpty else {
            fatalError("Password key was an empty array.")
        }
        
        guard !salt.isEmpty else {
            fatalError("Salt was an empty array.")
        }
        
        let cryptor = StreamCryptor(operation: .encrypt,
                                    algorithm: scheme.algorithm,
                                    mode: scheme.algorithmMode,
                                    padding: .PKCS7Padding,
                                    key: key,
                                    iv: [])
        
        let dataStream = InputStream(data: data)
        let outStream = OutputStream(toMemory: ())
        let bufferSize = scheme.bufferSize
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        guard let encryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Encrypted output stream didn't return data.")
        }
        
        return EncryptedItem(version: scheme.version, payload: encryptedData, salt: salt)
    }
    
    
    // MARK: - Decryption
    
    public static func data(withEncryptedObject object: EncryptedItem, password: String) throws -> Data {
        
        let scheme = Scheme(format: object.version)
        let data = object.payload
        let salt = object.salt
        
        let key = EncryptionSerialization.keyFromPassword(password, salt: salt, scheme: scheme)
        
        let cryptor = StreamCryptor(operation: .decrypt,
                                    algorithm: scheme.algorithm,
                                    mode: scheme.algorithmMode,
                                    padding: .PKCS7Padding,
                                    key: key,
                                    iv: [])
        
        let dataStream = InputStream(data: data)
        let outStream = OutputStream(toMemory: ())
        let bufferSize = scheme.bufferSize
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        guard let decryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Decrypted output stream didn't return data.")
        }
        
        return decryptedData
    }
    
    
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
