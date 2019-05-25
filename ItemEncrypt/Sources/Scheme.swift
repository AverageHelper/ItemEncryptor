//
//  Scheme.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto
import CommonCrypto

extension EncryptionSerialization {
    // MARK: Encryption Schemes
    
    public struct Scheme: Equatable, Hashable {
        // MARK: Spec Versions
        
        public enum Format {
            /// Version 1 of our encrypted data format. Derives with SHA256
            case pilot
            
            /// The latest version of the spec.
            static let latest: Format = .pilot
            /// The most common spec version to expect.
            static let primary: Format = .pilot
            
            /// A representation of the format in bytes.
            var rawValue: [UInt8] {
                switch self {
                case .pilot: return [0, 0, 1]
                }
            }
            
            /// Attempts to derive an `EncryptedItem.Format` from `bytes`, returning `nil` if an appropriate representation cannot be found.
            init?(bytes: [UInt8]) {
                if bytes == Format.pilot.rawValue {
                    self = .pilot
                    
                } else {
                    return nil
                }
            }
            
        }
        
        // MARK: - Properties
        
        /// The spec version used to encrypt data.
        let version: Format
        
        /// The pseudorandom algorithm we use to derive keys from passwords.
        var randomAlgorithm: PBKDF.PseudoRandomAlgorithm {
            switch self.version {
            case .pilot: return .sha256
            }
        }
        
        /// The pseudorandom algorithm we use to derive keys from other keys.
        var hmacAlgorithm: HMAC.Algorithm {
            switch self.version {
            case .pilot: return .sha256
            }
        }
        
        /// The number of bytes our key should be.
        var derivedKeyLength: KeySize {
            switch self.version {
            case .pilot: return .aes256
            }
        }
        
        /// The size of the encryption buffer to use.
        var bufferSize: Int {
            switch self.version {
            case .pilot: return 1024
            }
        }
        
        /// The number of bytes that a random inital seed should be.
        var seedSize: Int {
            switch self.version {
            case .pilot: return 16
            }
        }
        
        var stretchedSaltSize: Int {
            return hmacAlgorithm.digestLength()
        }
        
        /// The number of PBKDF2 iterations to run for key derivation.
        var iterations: UInt32 {
            switch self.version {
            case .pilot: return 100_000
            }
        }
        
        /// The encryption algorithm to use.
        var encryptionAlgorithm: StreamCryptor.Algorithm {
            switch self.version {
            case .pilot: return .aes
            }
        }
        
        /// The mode in which the `encryptionAlgorithm` runs.
        var algorithmMode: StreamCryptor.Mode {
            switch self.version {
            case .pilot: return .CBC
            }
        }
        
        /// The default specification.
        public static let `default` = Scheme(format: .primary)
        
        public init(format: Format) {
            self.version = format
        }
        
        public static func == (lhs: Scheme, rhs: Scheme) -> Bool {
            return lhs.version == rhs.version
        }
        
        public func hash(into hasher: inout Hasher) {
            hasher.combine(version.rawValue)
        }
        
    }
    
}


public struct EncryptionKey: Equatable, Hashable {
    // MARK: Properties
    
    let scheme: EncryptionSerialization.Scheme
    let initializationVector: [UInt8]
    let salt: [UInt8]
    let keyData: [UInt8]
    
    // MARK: - Constructing an Encryption Key
    
    /// Derives an encryption key from the given password string and any additional data provided using the given encryption scheme.
    ///
    /// - parameter untreatedPassword: The raw password string from the user. This password is trimmed of leading and trailing whitespace, and Unicode normalized before being used to derive the key.
    /// - parameter salt: Some data which is used in the encryption algorithm. This is to be retrieved from storage, or generated randomly for a new key, but it is not considered secure data. It MUST match the salt size configured in the given encryption `scheme`.
    /// - parameter scheme: The encryption scheme (algorithm and configuration) to use to derive the key.
    init(untreatedPassword: String, additionalData: [String] = [], seed: [UInt8], scheme: EncryptionSerialization.Scheme) {
        
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
        self.initializationVector = []
        
        self.keyData = EncryptionSerialization.deriveKey(password: treatedPassword,
                                                         salt: salt,
                                                         scheme: scheme)
    }
    
    init(untreatedPassword: String, treatedSalt: [UInt8], scheme: EncryptionSerialization.Scheme) {
        
        self.scheme = scheme
        
        // Trimmed and normalized password
        let treatedPassword = untreatedPassword.trimmingCharacters(in: .whitespacesAndNewlines).decomposedStringWithCompatibilityMapping
        
        // Treated salt
        guard treatedSalt.count == scheme.stretchedSaltSize else {
            fatalError("Incoming salt was the wrong size for the encryption scheme.")
        }
        
        self.salt = treatedSalt
        self.initializationVector = []
        
        self.keyData = EncryptionSerialization.deriveKey(password: treatedPassword,
                                                         salt: salt,
                                                         scheme: scheme)
    }
    
}

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
