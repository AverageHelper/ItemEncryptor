//
//  KeychainHandle+CryptoKit.swift
//  ItemEncrypt
//
//  Created on 12/16/19.
//
//  Using pointers from
//  https://developer.apple.com/documentation/cryptokit/storing_cryptokit_keys_in_the_keychain
//

import Foundation.NSData
import CryptoKit

public protocol SecKeyConvertible: CustomStringConvertible {
	/// Creates a key from an X9.63 representation.
	init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
	
	/// An X9.63 representation of the key.
	var x963Representation: Data { get }
}

extension SecKeyConvertible {
	/// A string version of the key for visual inspection.
	/// IMPORTANT: Never log the actual key data.
	public var description: String {
		return self.x963Representation.withUnsafeBytes { bytes in
			return "Key representation contains \(bytes.count) bytes."
		}
	}
}

/// A generic class which conforms to `SecKeyConvertible`.
/// Use of this class should only be incidental, and not be used for any long-running key tasks.
final class AnySecKey: SecKeyConvertible {
	private let data: ContiguousBytes
	
	init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes {
		self.data = x963Representation
	}
	
	var x963Representation: Data { data.dataRepresentation }
}

public protocol GenericPasswordConvertible: CustomStringConvertible {
	/// Creates a key from a raw representation.
	init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
	
	/// A raw representation of the key.
	var rawRepresentation: Data { get }
}

/// A generic class which conforms to `GenericPasswordConvertible`.
/// Use of this class should only be incidental, and not be used for any long-running key tasks.
final class AnyGenericKey: GenericPasswordConvertible {
	private let data: ContiguousBytes
	
	init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
		self.data = data
	}
	
	var rawRepresentation: Data { data.dataRepresentation }
}

extension GenericPasswordConvertible {
	/// A string version of the key for visual inspection.
	/// IMPORTANT: Never log the actual key data.
	public var description: String {
		return self.rawRepresentation.withUnsafeBytes { bytes in
			return "Key representation contains \(bytes.count) bytes."
		}
	}
}

extension ContiguousBytes {
	/// A `Data` instance created safely from the contiguous bytes without making any copies.
	var dataRepresentation: Data {
		return self.withUnsafeBytes { bytes in
			let cfdata = CFDataCreateWithBytesNoCopy(nil, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count, kCFAllocatorNull)
			return ((cfdata as NSData?) as Data?) ?? Data()
		}
	}
}

// MARK: - NIST Keys

@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P256.Signing.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P256.KeyAgreement.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P384.Signing.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P384.KeyAgreement.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P521.Signing.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension P521.KeyAgreement.PrivateKey: SecKeyConvertible, @retroactive CustomStringConvertible {}

// MARK: - Other Key Types

@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension Curve25519.KeyAgreement.PrivateKey: GenericPasswordConvertible, @retroactive CustomStringConvertible {}
@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension Curve25519.Signing.PrivateKey: GenericPasswordConvertible, @retroactive CustomStringConvertible {}

@available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *)
extension SymmetricKey: GenericPasswordConvertible, @retroactive CustomStringConvertible {
	public init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
		self.init(data: data)
	}
	
	public var rawRepresentation: Data {
		return dataRepresentation  // Contiguous bytes repackaged as a Data instance.
	}
}
