//
//  EncryptedItem.swift
//  ItemEncrypt
//
//  Created on 5/23/19.
//

import Foundation
import CryptoKit

/// A semantic representation of encrypted data, encapsulating the encryption scheme format,
/// the salt and initialization vector (IV) used to encrypt the data, and the encrypted
/// payload itself.
public struct EncryptedItem {
    
    /// An array of bytes used as a hashing salt.
    public typealias Salt = [UInt8]
    
    /// An array of bytes used as an initialization vector for hashing.
    public typealias IV = [UInt8]
    
    // MARK: Properties
    
    /// The encryption scheme format used to encrypt or decrypt this item.
    public let version: EncryptionSerialization.Scheme.Format
    
    /// The encrypted data.
    internal let ciphertext: Data
    
    /// Some data salt used to encrypt or decrypt the item.
    public let salt: Salt
    
    /// The initialization vector (IV) used to encrypt or decrypt the item.
    public let iv: IV
    
    /// A representation of the item in raw bytes.
    ///
    /// This is usually what you would store on disk, and would be serialized into a new `EncryptedItem` with `init(data:)`.
    public var rawData: Data {
        var res = version.rawValue
        res.append(contentsOf: iv)
        res.append(contentsOf: ciphertext)
        res.append(contentsOf: salt)
        
        return Data(res)
    }
    
    // MARK: - Constructing an Encrypted Item
    
    internal init(version: EncryptionSerialization.Scheme.Format,
                  payload: Data,
                  salt: Salt,
                  iv: IV) {
        self.version = version
        self.ciphertext = payload
        self.salt = salt
        self.iv = iv
    }
    
    @available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
    public init(_ sealedBox: ChaChaPoly.SealedBox) throws {
        self.version = .version2
        self.ciphertext = sealedBox.ciphertext
        self.salt = Salt(sealedBox.nonce)
        self.iv = IV(sealedBox.tag)
    }
    
    public init(_ other: EncryptedItem) {
        self = try! EncryptedItem(data: other.rawData)
    }
    
    /// Attempts to derive an `EncryptedItem` from given `data`. If the data is invalid, an error is thrown.
    public init(data: Data) throws {
        
        // Configuration tells us how to look at this data.
        var resultPayload = Data()
        var resultSalt = Salt()
        var resultIV = IV()
        var resultScheme = EncryptionSerialization.Scheme.default
        try EncryptedItem.parseData(data,
                                    into: &resultPayload,
                                    resultIV: &resultIV,
                                    resultSalt: &resultSalt,
                                    resultScheme: &resultScheme)
        
        self.version = resultScheme.version
        self.ciphertext = resultPayload
        self.salt = resultSalt
        self.iv = resultIV
    }
    
    /// Attempts to parse given data into semantic version format ID, salt, and payload blocks.
    private static func parseData(_ data: Data,
                                  into resultPayload: inout Data,
                                  resultIV: inout IV,
                                  resultSalt: inout Salt,
                                  resultScheme: inout EncryptionSerialization.Scheme) throws {
        
        // version + iv + payload + salt
        var mutableData = data
        
        // Find version
        let scheme = try EncryptedItem.scheme(from: mutableData)
        let versionSize = scheme.version.rawValue.count
        
        // Slice off our version data
        mutableData = mutableData.subdata(in: versionSize..<mutableData.endIndex)
        
        // Find ID
        let expectedIVSize = scheme.initializationVectorSize
        let expectedIVData = mutableData[mutableData.startIndex..<expectedIVSize]
        resultIV = IV(expectedIVData)
        
        // Slice off our IV data
        mutableData = mutableData.subdata(in: expectedIVSize..<mutableData.endIndex)
        
        // Find salt
        let expectedSaltSize = scheme.stretchedSaltSize
        let saltStart = mutableData.endIndex.advanced(by: -expectedSaltSize)
        let expectedSaltData = mutableData[saltStart..<mutableData.count]
        let proposedSalt = Salt(expectedSaltData)
        resultSalt = proposedSalt
        
        // Slice off our salt
        mutableData = mutableData.subdata(in: mutableData.startIndex..<saltStart)
        resultPayload = mutableData
    }
    
    private static func scheme(from ciphertext: Data) throws -> EncryptionSerialization.Scheme {
        let expectedVersionSize = EncryptionSerialization.Scheme.Format.dataSize
        let expectedVersionData = ciphertext[ciphertext.startIndex..<expectedVersionSize]
        guard let foundVersion =
            EncryptionSerialization.Scheme.Format(bytes: [UInt8](expectedVersionData)) else {
            throw EncryptionSerialization.DecryptionError.badData
        }
        return EncryptionSerialization.Scheme(format: foundVersion)
    }
    
}

extension EncryptedItem: Equatable, Hashable {
    
    public static func == (lhs: EncryptedItem, rhs: EncryptedItem) -> Bool {
        return lhs.rawData == rhs.rawData
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawData)
    }
    
}

@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension ChaChaPoly.SealedBox {
    
    public init(_ encryptedItem: EncryptedItem) throws {
        try self.init(nonce: ChaChaPoly.Nonce(data: encryptedItem.salt),
                      ciphertext: encryptedItem.ciphertext,
                      tag: encryptedItem.iv)
    }
    
}
