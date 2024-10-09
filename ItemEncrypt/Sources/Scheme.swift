//
//  Scheme.swift
//  ItemEncrypt
//
//  Created on 5/23/19.
//

import Foundation
import IDZSwiftCommonCrypto
import CryptoKit

extension EncryptionSerialization {
	// MARK: Encryption Schemes
	
	/// Defines constants that are used for encryption and decryption.
	public struct Scheme {
		// MARK: Spec Versions
		
		/// Encryption format information.
		///
		/// This defines the algorithms, key and buffer sizes, and other information
		/// specific to a particular encryption scheme.
		///
		/// We provide one here, but more may be added later as the need arises.
		public enum Format {
			
			typealias Bytes = [UInt8]
			
			/// The latest version of the spec.
			public static let latest: Format = .version1
			
			/// The most tested version of the spec.
			public static let primary: Format = .version1
			
			/// Version 1 of our encrypted data format.
			///
			/// Defines a scheme using AES-256 encryption in CBC mode, 100,000 iterations
			/// of PBKDF2 with SHA-256 hashing, a 1024-byte buffer, and 16-byte seeds and
			/// initialization vectors (IV).
			case version1
			
			/// Version 2 of our encrypted data format.
			///
			/// Defines a scheme using the ChaCha20-Poly1305 suite, 100,000 iterations of PBKDF2 and 256-bit hashing.
			@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
			case version2
			
			@available(*, deprecated, renamed: "version1")
			public static var pilot: Format { Format.version1 }
			
			/// A representation of the format in bytes.
			///
			/// This is used at runtime to identify the encryption scheme information
			/// from a block of data.
			internal var rawValue: Bytes {
				switch self {
				case .version1: return [0, 0, 1]
				case .version2: return [0, 0, 2]
				}
			}
			
			internal static var dataSize: Int {
				return 3
			}
			
			/// Attempts to derive an `EncryptedItem.Format` from an array of bytes,
			/// returning `nil` if an appropriate representation cannot be found.
			internal init?(bytes: Bytes) {
				if bytes == Format.version1.rawValue {
					self = .version1
					
				} else if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *),
									bytes == Format.version2.rawValue {
					self = .version2
					
				} else {
					return nil
				}
			}
			
		}
		
		// MARK: - Properties
		
		/// The hash function to use for PBKDF, HMAC, etc.
		@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
		internal var hashFunction: some HashFunction {
			switch self.version {
			case .version1: return SHA256()
			case .version2: return SHA256()
			}
		}
		
		/// The spec version used to encrypt data.
		public let version: Format
		
		/// The pseudorandom algorithm we use to derive keys from passwords.
		internal var randomAlgorithm: IDZSwiftCommonCrypto.PBKDF.PseudoRandomAlgorithm {
			switch self.version {
			case .version1: return .sha256
			case .version2: return .sha256
			}
		}
		
		/// The pseudorandom algorithm we use to derive keys from other keys.
		internal var hmacAlgorithm: IDZSwiftCommonCrypto.HMAC.Algorithm {
			switch self.version {
			case .version1: return .sha256
			case .version2: return .sha256
			}
		}
		
		/// The number of bytes our key should be.
		@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
		internal var keySize: SymmetricKeySize {
			switch self.version {
			case .version1: return SymmetricKeySize.bits256
			case .version2: return SymmetricKeySize.bits256
			}
		}
		
		/// The number of bytes our key should be.
		internal var derivedKeyLength: KeySize {
			switch self.version {
			case .version1: return .aes256
			case .version2: return .aes256
			}
		}
		
		/// The size of the encryption buffer to use.
		public var bufferSize: Int {
			switch self.version {
			case .version1: return 1024
			case .version2: return 1024
			}
		}
		
		/// The number of bytes that a random inital seed should be.
		public var seedSize: Int {
			switch self.version {
			case .version1: return 16
			case .version2: return 16
			}
		}
		
		/// The number of bytes that an initialization vector should be.
		public var initializationVectorSize: Int {
			switch self.version {
			case .version1: return 16
			case .version2: return 16
			}
		}
		
		public var stretchedSaltSize: Int {
			return hmacAlgorithm.digestLength()
		}
		
		/// The number of PBKDF2 iterations to run for key derivation.
		public var iterations: UInt32 {
			switch self.version {
			case .version1: return 100_000
			case .version2: return 100_000
			}
		}
		
		/// The encryption algorithm to use.
		internal var encryptionAlgorithm: IDZSwiftCommonCrypto.StreamCryptor.Algorithm {
			switch self.version {
			case .version1: return .aes
			case .version2: return .aes
			}
		}
		
		/// The mode in which the `encryptionAlgorithm` runs.
		internal var algorithmMode: IDZSwiftCommonCrypto.StreamCryptor.Mode {
			switch self.version {
			case .version1: return .CBC
			case .version2: return .CBC
			}
		}
		
		// MARK: - Constructing an Encryption Scheme
		
		/// The default specification. Defaults to `Format.primary`.
		public static let `default` = Scheme(format: .primary)
		
		/// Creates a new `Scheme` using the given `format` information.
		public init(format: Format) {
			self.version = format
		}
		
	}
	
}

extension EncryptionSerialization.Scheme: Equatable, Hashable {
	// implementations are auto-generated. Our only stored proerty is `version`.
}
