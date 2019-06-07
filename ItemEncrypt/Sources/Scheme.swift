//
//  Scheme.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

extension EncryptionSerialization {
    // MARK: Encryption Schemes
    
    /// Contains constants that are used for encryption.
    public struct Scheme {
        // MARK: Spec Versions
        
        /// Encryption format information.
        ///
        /// This defines the algorithms, key and buffer sizes, and other information
        /// specific to a particular encryption scheme.
        ///
        /// We provide one here, but more may be added later as the need arises.
        public enum Format {
            /// Version 1 of our encrypted data format.
            ///
            /// Defines a scheme using AES-256 encryption in CBC mode, 100,000 iterations
            /// of PBKDF2 with SHA-256 hashing, a 1024-byte buffer, and 16-byte seeds and
            /// initialization vectors (IV).
            case pilot
            
            /// The latest version of the spec.
            public static let latest: Format = .pilot
            
            /// The most tested version of the spec.
            public static let primary: Format = .pilot
            
            /// A representation of the format in bytes.
            ///
            /// This is used at runtime to identify the encryption scheme information
            /// from a block of data.
            internal var rawValue: [UInt8] {
                switch self {
                case .pilot: return [0, 0, 1]
//                case .unused: return [0, 0, 2]
                }
            }
            
            internal static var dataSize: Int {
                return 3
            }
            
            /// Attempts to derive an `EncryptedItem.Format` from an array of bytes,
            /// returning `nil` if an appropriate representation cannot be found.
            internal init?(bytes: [UInt8]) {
                if bytes == Format.pilot.rawValue {
                    self = .pilot
                    
//                } else if bytes == Format.unused.rawValue {
//                    self = .unused
                    
                } else {
                    return nil
                }
            }
            
        }
        
        // MARK: - Properties
        
        /// The spec version used to encrypt data.
        public let version: Format
        
        /// The pseudorandom algorithm we use to derive keys from passwords.
        internal var randomAlgorithm: PBKDF.PseudoRandomAlgorithm {
            switch self.version {
            case .pilot: return .sha256
//            case .unused: return .sha512
            }
        }
        
        /// The pseudorandom algorithm we use to derive keys from other keys.
        internal var hmacAlgorithm: HMAC.Algorithm {
            switch self.version {
            case .pilot: return .sha256
//            case .unused: return .sha512
            }
        }
        
        /// The number of bytes our key should be.
        internal var derivedKeyLength: KeySize {
            switch self.version {
            case .pilot: return .aes256
//            case .unused: return .tripleDES
            }
        }
        
        /// The size of the encryption buffer to use.
        public var bufferSize: Int {
            switch self.version {
            case .pilot: return 1024
//            case .unused: return 1024
            }
        }
        
        /// The number of bytes that a random inital seed should be.
        public var seedSize: Int {
            switch self.version {
            case .pilot: return 16
//            case .unused: return 16
            }
        }
        
        /// The number of bytes that an initialization vector should be.
        public var initializationVectorSize: Int {
            switch self.version {
            case .pilot: return 16
//            case .unused: return 16
            }
        }
        
        public var stretchedSaltSize: Int {
            return hmacAlgorithm.digestLength()
        }
        
        /// The number of PBKDF2 iterations to run for key derivation.
        public var iterations: UInt32 {
            switch self.version {
            case .pilot: return 100_000
//            case .unused: return 200_000
            }
        }
        
        /// The encryption algorithm to use.
        internal var encryptionAlgorithm: StreamCryptor.Algorithm {
            switch self.version {
            case .pilot: return .aes
//            case .unused: return .tripleDES
            }
        }
        
        /// The mode in which the `encryptionAlgorithm` runs.
        internal var algorithmMode: StreamCryptor.Mode {
            switch self.version {
            case .pilot: return .CBC
//            case .unused: return .CBC
            }
        }
        
        // MARK: - Constructing an Encryption Scheme
        
        /// The default specification. Defaults to `Format.primary`.
        public static let `default` = Scheme(format: .primary)
        
        public init(format: Format) {
            self.version = format
        }
        
    }
    
}

extension EncryptionSerialization.Scheme: Equatable, Hashable {
    // implementations are auto-generated. Our only stored proerty is `version`.
}
