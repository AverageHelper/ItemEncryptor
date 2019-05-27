//
//  KeychainHandle.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/24/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation
import Security


/// A simple interface for keeping and retrieving semantic `EncryptionKey` objects from the Keychain.
public class KeychainHandle {
    // MARK: Properties
    
    var description: String
    
    // MARK: - Constructing a Keychain Handle
    
    public init(description: String = "com.LeadDevCreations.ItemEncrypt.KeychainHandle Items") {
        self.description = description
    }
    
    // MARK: - Storing Keys
    
    /// Saves the given key on the Keychain, replacing any existing one by that tag.
    ///
    /// - parameter encryptionKey: The key to store.
    /// - parameter tag: The name to associate with the key for future retrieval. This should be in reverse-DNS notation.
    /// - throws: A `StorageError` if the save failed.
    /// - returns: The key that was stored in the keychain.
    @discardableResult
    public func setKey(_ encryptionKey: EncryptionKey, forTag tag: String) throws -> EncryptionKey {
        
        // Delete the existing key, if there is one.
        try deleteKey(withTag: tag)
        
        let key = encryptionKey.rawData as CFData
        
        // We store the "key" data as a "password". See answer to https://forums.developer.apple.com/thread/113321
        var addQuery: [String: Any] =
            [kSecClass as String: kSecClassGenericPassword,
             kSecAttrLabel as String: tag as CFString,
             kSecAttrIsInvisible as String: true as CFBoolean,
             kSecAttrCreationDate as String: Date() as CFDate,
             kSecValueData as String: key,
             kSecReturnData as String: true as CFBoolean]
        
        // Save the context under "account"
        if let account = encryptionKey.context {
            addQuery[kSecAttrAccount as String] = account
        }
        
        #if os(macOS)
        if #available(OSX 10.0, *) {
            var access: SecAccess?
            let accessStatus = SecAccessCreate(self.description as CFString, nil, &access)
            
            guard accessStatus == errSecSuccess else {
                // Throw the error
                let explanation = SecCopyErrorMessageString(accessStatus, nil) ?? "Unknown reason." as CFString
                throw StorageError.unknown(reason: explanation as String)
            }
            
            addQuery[kSecAttrAccess as String] = access!
        }
        #endif

        var result: CFTypeRef?
        let status = SecItemAdd(addQuery as CFDictionary, &result)
        
        switch status {
        case errSecSuccess,
             errSecItemNotFound: break
            
        case errSecDuplicateItem:
            // Item already there
            throw StorageError.duplicateItem
            
        default:
            // Handle error
            try handleGenericError(status: status)
        }
        
        // Expect plain data as the result
        guard let data = result as? Data else {
            throw StorageError.incorrectContents
        }
        
        return try EncryptionKey(data: data)
    }
    
    // MARK: - Querying Keys
    
    /// Retrieves the encryption key with the given `tag`.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to retrieve appropriate data, or if the data found with the given `tag` is not a valid `EncryptionKey`.
    /// - returns: The key, or `nil` if no data exists in the keychain with the given `tag`.
    public func key(withTag tag: String) throws -> EncryptionKey? {
        
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: tag,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        var itemRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &itemRef)
        
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound:
            // No data? Return nothing.
            return nil
            
        default:
            // Handle error
            try handleGenericError(status: status)
        }
        
        // Get the item dictionary
        guard let item = itemRef as? [String: Any],
               let keyData = item[kSecValueData as String] as? Data
        else {
            // Item didn't come out as a dictionary, or Data wasn't found in that dictionary? Throw!
            throw StorageError.incorrectContents
        }
        
        var key = try EncryptionKey(data: keyData)
        // Store the context on if it exists.
        key.context = item[kSecAttrAccount as String] as? String
        
        return key
    }
    
    // MARK: - Deleting Keys
    
    /// Deletes the data with the given `tag` from the keychain.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to delete the data with the given `tag`.
    /// - returns: The `EncryptionKey` which was deleted, or `nil` if there was no data with `tag`, or if that data wasn't an `EncryptionKey`.
    @discardableResult
    public func deleteKey(withTag tag: String) throws -> EncryptionKey? {
        
        // If this fails for bad data, we're deleting the data anyway.
        let existingKey = try? key(withTag: tag)
        
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: tag]
        
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound:
            // No data? Great!
            return nil
            
        default:
            // Handle error
            try handleGenericError(status: status)
        }
        
        return existingKey
    }
    
    // MARK: - Handling Errors
    
    public enum StorageError: Error {
        case badRequest
        case cancelled
        case diskFull
        case duplicateItem
        case incorrectContents
        case invalidParameters
        case invalidValueDetected
        case ioError
        case itemNotFound
        case memoryError(reason: String)
        case unknown(reason: String)
    }
    
    private func handleGenericError(status: OSStatus) throws {
        switch status {
        case errSecSuccess:      break
        case errSecAllocate:     throw StorageError.memoryError(reason: "Failed to allocate memory")
        case errSecBadReq:       throw StorageError.badRequest
        case errSecDiskFull, errSecDskFull: throw StorageError.diskFull
        case errSecItemNotFound: throw StorageError.itemNotFound
        case errSecIO:           throw StorageError.ioError
        case errSecInvalidValue: throw StorageError.invalidValueDetected
        case errSecMemoryError:  throw StorageError.memoryError(reason: "Generic")
        case errSecParam:        throw StorageError.invalidParameters
        case errSecUserCanceled: throw StorageError.cancelled
            
        default:
            // Throw the error
            let explanation = SecCopyErrorMessageString(status, nil) ?? "Unknown reason." as CFString
            throw StorageError.unknown(reason: explanation as String)
        }
    }
    
}
