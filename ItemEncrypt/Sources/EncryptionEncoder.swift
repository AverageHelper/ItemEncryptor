//
//  EncryptionEncoder-Archiver.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/27/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation

//===----------------------------------------------------------------------===//
// Encryption Encoder
//===----------------------------------------------------------------------===//

/// `EncryptionEncoder` facilitates the encoding of `Encodable` values into a secure form.
public final class EncryptionEncoder {
    // MARK: Options
    
    /// The encryption configuration to use when encoding input data.
    public let configuration: EncryptionSerialization.Scheme
    
    /// Contextual user-provided information for use during encoding.
    public var userInfo = [CodingUserInfoKey: Any]()
    
    // MARK: - Constructing an Encryption Encoder
    
    public init(configuration: EncryptionSerialization.Scheme = .default) {
        self.configuration = configuration
    }
    
    // MARK: - Encoding Values
    
    /// Encodes the given top-level value and returns its uniquely encrypted representation.
    ///
    /// - parameter value: The value to encode.
    /// - parameter password: The password from which a new random key is derived. This key
    ///     is used to encrypt the given `value`. This password is not retained past the
    ///     lifetime of the function call.
    /// - returns: A new `Data` value containing the encoded data.
    /// - throws: An `EncodingError` if any value throws an error during encoding.
    public func encode<T: Encodable>(_ value: T,
                                     withPassword password: String) throws -> EncryptedItem {
        
        let archiver = NSKeyedArchiver(requiringSecureCoding: false)
        archiver.outputFormat = .binary
        
        try archiver.encodeEncodable(value, forKey: NSKeyedArchiveRootObjectKey)
        let data = archiver.encodedData
        
        return try EncryptionSerialization.encryptedItem(with: data,
                                                         password: password,
                                                         scheme: configuration)
    }
    
    /// Encodes the given top-level value using the given key, and returns its encrypted representation.
    ///
    /// - parameter value: The value to encode.
    /// - parameter key: The encryption key to use when encoding the `value`. This or an identical key may be used for later decryption.
    /// - returns: A new `Data` value containing the encoded data.
    /// - throws: An `EncodingError` if any value throws an error during encoding.
    public func encode<T: Encodable>(_ value: T,
                                     withKey key: EncryptionKey) throws -> EncryptedItem {
        
        let archiver = NSKeyedArchiver(requiringSecureCoding: false)
        archiver.outputFormat = .binary
        
        try archiver.encodeEncodable(value, forKey: NSKeyedArchiveRootObjectKey)
        let data = archiver.encodedData
        
        return EncryptionSerialization.encryptedItem(with: data, key: key)
    }
    
}

//===----------------------------------------------------------------------===//
// Encryption Decoder
//===----------------------------------------------------------------------===//

/// `EncryptionDecoder` facilitates the decoding of encrypted data into semantic
/// `Decodable` types.
public final class EncryptionDecoder {
    // MARK: Options
    
    /// The encryption configuration to use when decoding input data.
    public let configuration: EncryptionSerialization.Scheme
    
    /// Contextual user-provided information for use during decoding.
    public var userInfo: [CodingUserInfoKey: Any] = [:]
    
    // MARK: - Constructing an Encryption Decoder
    
    public init(configuration: EncryptionSerialization.Scheme = .default) {
        self.configuration = configuration
    }
    
    // MARK: - Decoding Values
    
    /// Decodes a top-level value of the given type from the given encrypted representation.
    ///
    /// - parameter type: The type of the value to decode.
    /// - parameter item: The item to decode.
    /// - parameter password: The password to use for decrypting `item`. This password is
    ///     **never** retained beyond the lifetime of this function's call stack.
    /// - returns: A value of the requested type.
    /// - throws: A `DecryptionError` if the decryption fails, or a `DecodingError` if the
    ///     item couldn't be decoded as the given `type`.
    public func decode<T: Decodable>(_ type: T.Type,
                                     from item: EncryptedItem,
                                     withPassword password: String) throws -> T {
        
        // Decrypt the archive
        let data = try EncryptionSerialization.data(fromEncryptedObject: item,
                                                       password: password)
        
        do {
            let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
            unarchiver.decodingFailurePolicy = .setErrorAndReturn
            
            // Attempt to decode the semantic `type`
            guard let object = unarchiver.decodeDecodable(type, forKey: NSKeyedArchiveRootObjectKey) else {
                throw DecodingError.valueNotFound(type, DecodingError.Context(codingPath: [], debugDescription: "The given data did not contain a top-level value of type \(type)."))
            }
            return object
            
        } catch let error as DecodingError {
            throw error
            
        } catch {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "The decrypted data came invalid. Perhaps an incorrect password?", underlyingError: error))
        }
    }
    
    /// Decodes a top-level value of the given type from the given encrypted representation.
    ///
    /// - parameter type: The type of the value to decode.
    /// - parameter item: The item to decode.
    /// - parameter key: The key to use for decrypting `item`. This key is **never**
    ///     retained beyond the lifetime of this function's call stack.
    /// - returns: A value of the requested type.
    /// - throws: A `DecryptionError` if the decryption fails, or a `DecodingError` if the
    ///     item couldn't be decoded as the given `type`.
    public func decode<T: Decodable>(_ type: T.Type,
                                     from item: EncryptedItem,
                                     withKey key: EncryptionKey) throws -> T {
        
        // Decrypt the archive
        let data = try EncryptionSerialization.data(fromEncryptedObject: item, key: key)
        
        do {
            let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
            unarchiver.decodingFailurePolicy = .setErrorAndReturn
            
            // Attempt to decode the semantic `type`
            guard let object = unarchiver.decodeDecodable(type, forKey: NSKeyedArchiveRootObjectKey) else {
                throw DecodingError.valueNotFound(type, DecodingError.Context(codingPath: [], debugDescription: "The given data did not contain a top-level value of type \(type)."))
            }
            return object
            
        } catch let error as DecodingError {
            throw error
            
        } catch {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: [], debugDescription: "The decrypted data came invalid. Perhaps an incorrect password?", underlyingError: error))
        }
    }
    
}
