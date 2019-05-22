//
//  API.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation

public struct EncryptedItem {
    
    public enum Format {
        /// The first version of our encryoted data format.
        case pilot
        
        var rawValue: [UInt8] {
            switch self {
            case .pilot: return [0, 0, 1]
            }
        }
        
        init?(bytes: [UInt8]) {
            if bytes == Format.pilot.rawValue {
                self = .pilot
                
            } else {
                return nil
            }
        }
        
    }
    
    fileprivate let version: Format
    fileprivate let payload: Data
    fileprivate let salt: [UInt8]
    
    
    public var rawData: Data {
        return version.rawValue + payload + salt
    }
    
    internal init(version: Format = .pilot, payload: Data, salt: [UInt8]) {
        self.version = version
        self.payload = payload
        self.salt = salt
    }
    
    /// Attempts to derive an `EncryptedItem` from `data` with the given `configuration`
    ///   specifications. If the given version is found not to match the configuration's
    ///   version spec, a `DecryptionError` is thrown.
    init(data: Data, usingConfiguration configuration: EncryptionSerialization.Configuration) throws {
        // Configuration tells us how to look at this data.
        
        var resultPayload = Data()
        var resultSalt = [UInt8]()
        try EncryptedItem.parseData(data,
                                    into: &resultPayload,
                                    resultSalt: &resultSalt,
                                    version: configuration.version,
                                    saltSize: configuration.saltSize)
        
        self.version = configuration.version
        self.payload = resultPayload
        self.salt = resultSalt
    }
    
    private static func parseData(_ data: Data,
                                  into resultPayload: inout Data,
                                  resultSalt: inout [UInt8],
                                  version: Format,
                                  saltSize expectedSaltSize: Int) throws {
        
        // version + payload + salt
        var mutableData = data
        
        let expectedVersionSize = version.rawValue.count
        let expectedVersionData = mutableData[mutableData.startIndex..<expectedVersionSize]
        guard let foundVersion = Format(bytes: [UInt8](expectedVersionData)) else {
            throw EncryptionSerialization.DecryptionError.badData
        }
        guard foundVersion == version else {
            throw EncryptionSerialization.DecryptionError.incorrectVersion
        }
        
        mutableData = mutableData.subdata(in: (expectedVersionSize - 1)..<mutableData.endIndex)
        
        let saltStart = data.endIndex.advanced(by: -expectedSaltSize)
        let expectedSaltData = data[saltStart..<data.count]
        let proposedSalt = [UInt8](expectedSaltData)
        resultSalt = proposedSalt
        
        mutableData = mutableData.subdata(in: mutableData.startIndex..<saltStart)
        resultPayload = mutableData
    }
    
}

public final class EncryptionSerialization {
    // MARK: Configuration
    
    public struct Configuration {
        
        let version: EncryptedItem.Format
        
        var bufferSize: Int {
            switch version {
            case .pilot: return 1024
            }
        }
        
        /// The size of the salt, in bytes, that will be kept at the end of the data.
        var saltSize: Int {
            switch version {
            case .pilot: return 16
            }
        }
        
        var iterations: UInt32 {
            switch version {
            case .pilot: return 100_000
            }
        }
        
        public init(format: EncryptedItem.Format) {
            self.version = format
        }
        
        /// The default configuration to construct an `ItemEncryptor` class object.
        public static let `default` = Configuration(format: .pilot)
        
    }
    
    public enum DecryptionError: Error {
        case badData
        case incorrectVersion
    }
    
    // MARK: - Properties
    
    public var configuration: Configuration
    
    // MARK: - Key Derivation
    
    init(configuration: Configuration) {
        self.configuration = configuration
    }
    
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
    
    // MARK: Encryption
    
    /// Performs SHA256 encryption on `data`, using a key generated from `password`.
    ///
    /// A key is generated using PBKDF and a cryptographically random salt, which is
    ///   attached to the returned object for later use in decryption.
    ///
    /// - Parameter data: A data block to be encrypted.
    /// - Parameter passwordKey: The password key by which to encrypt the data. This must
    ///     not be empty.
    /// - Returns: An `EncryptedItem` representing the encrypted data.
    public func encryptedItem(from data: Data, passwordKey key: [UInt8], salt: [UInt8]) -> EncryptedItem {
        
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
        let bufferSize = configuration.bufferSize
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        guard let encryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Encrypted output stream didn't return data.")
        }
        
        return EncryptedItem(payload: encryptedData, salt: salt)
    }
    
    
    // MARK: Decryption
    
    public func decryptedData(from object: EncryptedItem, password: String) throws -> Data {
        
        let data = object.payload
        let salt = object.salt
        
        let key = EncryptionSerialization.keyFromPassword(password, salt: salt, iterations: configuration.iterations)
        
        let cryptor = StreamCryptor(operation: .decrypt,
                                    algorithm: .aes,
                                    mode: .CBC,
                                    padding: .PKCS7Padding,
                                    key: key,
                                    iv: [UInt8]())
        
        let dataStream = InputStream(data: data)
        let outStream = OutputStream(toMemory: ())
        let bufferSize = configuration.bufferSize
        
        EncryptionSerialization.crypt(sc: cryptor, inputStream: dataStream, outputStream: outStream, bufferSize: bufferSize)
        
        guard let decryptedData = outStream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
            fatalError("Decrypted output stream didn't return data.")
        }
        
        return decryptedData
    }
    
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
