//
//  EncryptionKey.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/24/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

public struct EncryptionKey: Equatable, Hashable {
    // MARK: Properties
    
    public let scheme: EncryptionSerialization.Scheme
    public let keyData: [UInt8]
    public let initializationVector: [UInt8]
    public let salt: [UInt8]
    public var context: String?
    
    public var rawData: Data {
        // version + payload + iv + salt
        
        var res = scheme.version.rawValue
        res.append(contentsOf: keyData)
        res.append(contentsOf: initializationVector)
        res.append(contentsOf: salt)
        
        return Data(res)
    }
    
    // MARK: - Constructing an Encryption Key
    
    /// Derives a random encryption key from the given password string and any additional data provided using the given encryption scheme.
    ///
    /// - important: This function generates a random seed (using `EncryptionSerialization.randomBytes(count:)`) for the key. DO NOT expect passing the same data to generate the same key.
    ///
    /// - parameter password: The raw password string from the user. This password is trimmed of leading and trailing whitespace, and Unicode normalized before being used to derive the key.
    /// - parameter additionalData: Any array of contextual information (such as an account ID, email address, etc.) which should be closely tied to the derived key.
    /// - parameter scheme: The encryption scheme (algorithm and configuration) to use to derive the key.
    public init(randomKeyFromPassword password: String, additionalData: [String] = [], scheme: EncryptionSerialization.Scheme) {
        let seed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let iv = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        self.init(untreatedPassword: password,
                  additionalData: additionalData,
                  seed: seed,
                  iv: iv,
                  scheme: scheme)
    }
    
    /// Derives an encryption key from the given password string and any additional data provided using the given encryption scheme.
    ///
    /// - parameter untreatedPassword: The raw password string from the user. This password is trimmed of leading and trailing whitespace, and Unicode normalized before being used to derive the key.
    /// - parameter salt: Some data which is used in the encryption algorithm. This is to be retrieved from storage, or generated randomly for a new key, but it is not considered secure data. It MUST match the salt size configured in the given encryption `scheme`.
    /// - parameter scheme: The encryption scheme (algorithm and configuration) to use to derive the key.
    public init(untreatedPassword: String, additionalData: [String] = [], seed: [UInt8], iv: [UInt8], scheme: EncryptionSerialization.Scheme) {
        
        self.scheme = scheme
        
        // Trimmed and normalized password
        let treatedPassword = untreatedPassword.trimmingCharacters(in: .whitespacesAndNewlines).decomposedStringWithCompatibilityMapping
        
        // Treated salt
        guard seed.count == scheme.seedSize else {
            fatalError("Incoming seed was the wrong size for the encryption scheme.")
        }
        
        var hasher = HMAC(algorithm: scheme.hmacAlgorithm, key: seed)
        for data in additionalData {
            // Hash in the email, user ID, etc. passed in.
            hasher = hasher.update(string: data)!
        }
        
        self.salt = hasher.final()
        self.initializationVector = iv
        
        self.keyData = EncryptionSerialization.deriveKey(password: treatedPassword,
                                                         salt: salt,
                                                         scheme: scheme)
    }
    
    public init(untreatedPassword: String, treatedSalt: [UInt8], iv: [UInt8], scheme: EncryptionSerialization.Scheme) {
        
        self.scheme = scheme
        
        // Trimmed and normalized password
        let treatedPassword = untreatedPassword.trimmingCharacters(in: .whitespacesAndNewlines).decomposedStringWithCompatibilityMapping
        
        // Treated salt
        guard treatedSalt.count == scheme.stretchedSaltSize else {
            fatalError("Incoming salt was the wrong size for the encryption scheme.")
        }
        
        self.salt = treatedSalt
        self.initializationVector = iv
        
        self.keyData = EncryptionSerialization.deriveKey(password: treatedPassword,
                                                         salt: salt,
                                                         scheme: scheme)
    }
    
    public init(data: Data) throws {
        // Configuration tells us how to look at this data.
        
        var iv = [UInt8]()
        var salt = [UInt8]()
        var keyData = [UInt8]()
        var version = EncryptionSerialization.Scheme.Format.primary
        
        self.scheme = try EncryptionKey.parseData(data,
                                                  into: &keyData,
                                                  initializationVector: &iv,
                                                  resultSalt: &salt,
                                                  version: &version)
        
        self.initializationVector = iv
        self.salt = salt
        self.keyData = keyData
    }
    
    /// Attempts to parse given data into semantic version format ID, innitialization vector, salt, and payload blocks.
    private static func parseData(_ data: Data,
                                  into resultPayload: inout [UInt8],
                                  initializationVector: inout [UInt8],
                                  resultSalt: inout [UInt8],
                                  version: inout EncryptionSerialization.Scheme.Format) throws -> EncryptionSerialization.Scheme {
        
        // version + payload + iv + salt
        var mutableData = data
        
        // Get version
        let expectedVersionSize = EncryptionSerialization.Scheme.Format.dataSize
        let expectedVersionData = mutableData[mutableData.startIndex..<expectedVersionSize]
        guard let foundVersion =
            EncryptionSerialization.Scheme.Format(bytes: [UInt8](expectedVersionData)) else {
                throw EncryptionSerialization.DecryptionError.badData
        }
        version = foundVersion
        
        mutableData = mutableData.subdata(in: expectedVersionSize..<mutableData.endIndex)
        let scheme = EncryptionSerialization.Scheme(format: version)
        
        // Get salt
        let saltSize = scheme.stretchedSaltSize
        let saltStart = mutableData.endIndex.advanced(by: -saltSize)
        let expectedSaltData = mutableData[saltStart..<mutableData.count]
        resultSalt = [UInt8](expectedSaltData)
        
        mutableData = mutableData.subdata(in: mutableData.startIndex..<saltStart)
        
        // Get initialization vector
        let vectorSize = scheme.initializationVectorSize
        let vectorStart = mutableData.endIndex.advanced(by: -vectorSize)
        let expectedVectorData = mutableData[vectorStart..<mutableData.count]
        initializationVector = [UInt8](expectedVectorData)
        
        mutableData = mutableData.subdata(in: mutableData.startIndex..<vectorStart)
        
        resultPayload = [UInt8](mutableData)
        
        return scheme
    }
    
}

// MARK: - Equatable and Hashable

extension EncryptionKey {
    
    public static func == (lhs: EncryptionKey, rhs: EncryptionKey) -> Bool {
        return lhs.scheme == rhs.scheme &&
            lhs.initializationVector == rhs.initializationVector &&
            lhs.salt == rhs.salt &&
            lhs.keyData == rhs.keyData
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(scheme)
        hasher.combine(initializationVector)
        hasher.combine(salt)
        hasher.combine(keyData)
    }
    
}
