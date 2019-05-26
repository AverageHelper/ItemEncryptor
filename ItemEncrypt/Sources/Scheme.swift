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
            
            static var dataSize: Int {
                return 3
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
        public let version: Format
        
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
        public var bufferSize: Int {
            switch self.version {
            case .pilot: return 1024
            }
        }
        
        /// The number of bytes that a random inital seed should be.
        public var seedSize: Int {
            switch self.version {
            case .pilot: return 16
            }
        }
        
        /// The number of bytes that an initialization vector should be.
        public var initializationVectorSize: Int {
            switch self.version {
            case .pilot: return 16
            }
        }
        
        public var stretchedSaltSize: Int {
            return hmacAlgorithm.digestLength()
        }
        
        /// The number of PBKDF2 iterations to run for key derivation.
        public var iterations: UInt32 {
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
