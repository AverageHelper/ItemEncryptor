//
//  API.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation


// MARK: - EncryptionSerialization

public enum EncryptionSerialization {
    // MARK: Options
    
    public struct Specification {
        
        /// The spec version used to encrypt data.
        let version: EncryptedItem.Format
        
        var bufferSize: Int {
            switch self.version {
            case .pilot: return 1024
            }
        }
        
        /// The size of the salt, in bytes, that will be kept at the end of the data.
        var saltSize: Int {
            switch self.version {
            case .pilot: return 16
            }
        }
        
        var iterations: UInt32 {
            switch self.version {
            case .pilot: return 100_000
            }
        }
        
        public init(format: EncryptedItem.Format) {
            self.version = format
        }
        
        /// The default specification.
        public static let `default` = Specification(format: .pilot)
        
    }
    
    public enum DecryptionError: Error {
        case badData
        case incorrectVersion
    }
    
    // MARK: - Key Derivation
    
    public static func keyFromPassword(_ password: String, saltSize: Int, iterations: Int) -> (key: [UInt8], salt: [UInt8]) {
        return keyFromPassword(password, saltSize: saltSize, iterations: UInt32(iterations))
    }
    
    public static func keyFromPassword(_ password: String, saltSize: Int, iterations: UInt32) -> (key: [UInt8], salt: [UInt8]) {
        let salt = try! Random.generateBytes(byteCount: saltSize)
        let key = keyFromPassword(password, salt: salt, iterations: iterations)
        return (key: key, salt: salt)
    }
    
    fileprivate static func keyFromPassword(_ password: String, salt: [UInt8], iterations: UInt32) -> [UInt8] {
        let key = PBKDF.deriveKey(password: password,
                                  salt: salt,
                                  prf: .sha256,
                                  rounds: iterations,
                                  derivedKeyLength: KeySize.aes256.rawValue)
        return key
    }
    
    // MARK: - Encryption
    
    /// Performs SHA256 encryption on `data`, using a key generated from `password`.
    ///
    /// A key is generated using PBKDF and a cryptographically random salt, which is
    ///   attached to the returned object for later use in decryption.
    ///
    /// - parameter data: A data block to be encrypted.
    /// - parameter passwordKey: The password key by which to encrypt the data. This must
    ///     not be empty.
    /// - parameter salt: A glob of nonsecure bytes which was used to derive the password key. This is kept with the encrypted data.
    /// - parameter options: The set of configuration options to use when encrypting the data.
    /// - returns: An `EncryptedItem` representing the encrypted data.
    public static func encryptedItem(with data: Data, passwordKey key: [UInt8], salt: [UInt8], options: Specification) -> EncryptedItem {
        
        guard !key.isEmpty else {
            fatalError("Password key was an empty array.")
        }
        
        guard !salt.isEmpty else {
            fatalError("Salt was an empty array.")
        }
        
        let cryptor = StreamCryptor(operation: .encrypt,
                                    algorithm: .aes,
                                    mode: .CBC,
                                    padding: .PKCS7Padding,
                                    key: key,
                                    iv: [UInt8]())
        
        let dataStream = InputStream(data: data)
        let outStream = OutputStream(toMemory: ())
        let bufferSize = options.bufferSize
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        guard let encryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Encrypted output stream didn't return data.")
        }
        
        return EncryptedItem(payload: encryptedData, salt: salt)
    }
    
    
    // MARK: - Decryption
    
    public static func data(withEncryptedObject object: EncryptedItem, password: String) throws -> Data {
        
        let options = Specification(format: object.version)
        let data = object.payload
        let salt = object.salt
        
        let key = EncryptionSerialization.keyFromPassword(password, salt: salt, iterations: options.iterations)
        
        let cryptor = StreamCryptor(operation: .decrypt,
                                    algorithm: .aes,
                                    mode: .CBC,
                                    padding: .PKCS7Padding,
                                    key: key,
                                    iv: [UInt8]())
        
        let dataStream = InputStream(data: data)
        let outStream = OutputStream(toMemory: ())
        let bufferSize = options.bufferSize
        
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
