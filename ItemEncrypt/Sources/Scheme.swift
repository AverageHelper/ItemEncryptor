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
    
    public struct Scheme {
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
        
        /// The pseudorandom algorithm we use to derive keys.
        var randomAlgorithm: PBKDF.PseudoRandomAlgorithm {
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
        
        /// The number of bytes that the salt should be.
        var saltSize: Int {
            switch self.version {
            case .pilot: return 16
            }
        }
        
        /// The number of PBKDF2 iterations to run for key derivation.
        var iterations: UInt32 {
            switch self.version {
            case .pilot: return 100_000
            }
        }
        
        /// The encryption algorithm to use.
        var algorithm: StreamCryptor.Algorithm {
            switch self.version {
            case .pilot: return .aes
            }
        }
        
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
        
    }
    
}
