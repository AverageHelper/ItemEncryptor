//
//  KeychainHandle.swift
//  ItemEncrypt
//
//  Created on 5/24/19.
//

import Foundation
import Security


/// A simple interface for storing semantic `EncryptionKey`s in the Keychain.
@available(*, deprecated, message: "Use another package, like kishikawakatsumi's KeychainAccess, instead.")
public final class KeychainHandle {
    // MARK: Properties
    
    /// A brief string used to describe your application's access to the Keychain. This
    /// string may be presented to the user when an application is trying to access our key
    /// data, such as from Keychain Access in macOS, or by some other means.
    public var description: String
    
    // MARK: - Constructing a Keychain Handle
    
    /// Creates a new Keychain handle, giving it a `description`.
    ///
    /// This does not create new Keychain storage, simply a new handle by which to access
    /// the same system Keychain. In macOS, the `description` is attached to the Keychain
    /// items you store, and is presented to users requesting access to them from outside of
    /// your app (usually a bad thing).
    ///
    /// - parameter description: A string which, in macOS, is is attached to the Keychain
    /// items you store, and is presented to users requesting access to them from outside of
    /// your app (usually a bad thing).
    public init(description: String = "com.LeadDevCreations.ItemEncrypt.KeychainHandle Items") {
        self.description = description
    }
    
    // MARK: - Storing Keys
    
    /// Saves the given key on the Keychain, replacing any existing one by that tag.
    ///
    /// - parameter encryptionKey: The key to store.
    /// - parameter tag: The name to associate with the key for future retrieval. This should be in reverse-DNS notation.
    /// - parameter account: Some text to put in the `account` field for the key in the keychan.
    ///
    /// - throws: A `StorageError` if the save failed.
    /// - returns: The key that was stored in the keychain.
    @discardableResult
    // swiftlint:disable:next function_body_length
    public func setKey<K: SecKeyConvertible>(_ encryptionKey: K, account: String?, forTag tag: String) throws -> K {
        
        // Delete the existing key, if there is one.
        _ = try deleteKey(withTag: tag) as K?
        
        let keyData = encryptionKey.x963Representation as CFData
        
        var attributes: [String: Any] =
            [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        
        var error: Unmanaged<CFError>?
        defer { error?.release() }
        guard let key = SecKeyCreateWithData(keyData as CFData,
                                             attributes as CFDictionary,
                                             &error)
            else {
                throw StorageError.unknown(reason: "Could not create SecKey representation due to error: \(String(describing: error))")
        }
        
        var addQuery: [String: Any] =
            [kSecClass as String: kSecClassKey,
             kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
             kSecAttrLabel as String: tag as CFString,
             kSecAttrIsInvisible as String: true as CFBoolean,
             kSecAttrCreationDate as String: Date() as CFDate,
             kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
             kSecValueRef as String: key,
             kSecReturnData as String: true as CFBoolean]
        
        // Save the context under "account"
        if let account = account {
            addQuery[kSecAttrAccount as String] = account
        }
        
        if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) {
            addQuery[kSecUseDataProtectionKeychain as String] = true as CFBoolean
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
            
        default:
            // Handle error
            try handleGenericError(status: status)
        }
        
        // Expect plain data as the result
        guard let data = result as? Data else {
            throw StorageError.incorrectContents
        }
        
        return try K(x963Representation: data)
    }
    
    /// Saves the given key on the Keychain, replacing any existing one by that tag.
    ///
    /// - parameter encryptionKey: The key to store.
    /// - parameter tag: The name to associate with the key for future retrieval. This should be in reverse-DNS notation.
    /// - parameter account: Some text to put in the `account` field for the key in the keychan.
    ///
    /// - throws: A `StorageError` if the save failed.
    /// - returns: The key that was stored in the keychain.
    @discardableResult
    public func setKey<K: GenericPasswordConvertible>(_ encryptionKey: K, account: String?, forTag tag: String) throws -> K {
        
        // Delete the existing key, if there is one.
        _ = try deleteKey(withTag: tag) as K?
        
        let key = encryptionKey.rawRepresentation as CFData
        
        // We store the "key" data as a "password". See answer to https://forums.developer.apple.com/thread/113321
        var addQuery: [String: Any] =
            [kSecClass as String: kSecClassGenericPassword,
             kSecAttrLabel as String: tag as CFString,
             kSecAttrIsInvisible as String: true as CFBoolean,
             kSecAttrCreationDate as String: Date() as CFDate,
             kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
             kSecValueData as String: key,
             kSecReturnData as String: true as CFBoolean]
        
        // Save the context under "account"
        if let account = account {
            addQuery[kSecAttrAccount as String] = account
        }
        
        if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) {
            addQuery[kSecUseDataProtectionKeychain as String] = true as CFBoolean
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
            
        default:
            // Handle error
            try handleGenericError(status: status)
        }
        
        // Expect plain data as the result
        guard let data = result as? Data else {
            throw StorageError.incorrectContents
        }
        
        return try K(rawRepresentation: data)
    }
    
    /// Saves the given key on the Keychain, replacing any existing one by that tag.
    ///
    /// - parameter encryptionKey: The key to store.
    /// - parameter tag: The name to associate with the key for future retrieval. This should be in reverse-DNS notation.
    ///
    /// - throws: A `StorageError` if the save failed.
    /// - returns: The key that was stored in the keychain.
    @discardableResult
    public func setKey(_ encryptionKey: EncryptionKey, forTag tag: String) throws -> EncryptionKey {
        return try setKey(encryptionKey, account: encryptionKey.context, forTag: tag)
    }
    
    // MARK: - Querying Keys
    
    /// Retrieves the encryption key with the given `tag`.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to retrieve appropriate data, or if the data found with the given `tag` is not a valid key type.
    /// - returns: The key, or `nil` if no data exists in the keychain with the given `tag`.
    public func key<K: SecKeyConvertible>(withTag tag: String) throws -> K? {
        
        var query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrLabel as String: tag,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnRef as String: true]
        
        if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        
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
        
        let secKey = itemRef as! SecKey
        var error: Unmanaged<CFError>?
        defer { error?.release() }
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw StorageError.unknown(reason: "Could not serialize SecKey data from representation due to error: \(String(describing: error))")
        }
        let key = try K(x963Representation: data)
        
        // Store the context on if it exists.
        if let encKey = key as? EncryptionKey {
            encKey.context = itemRef![kSecAttrAccount as String] as? String
        }
        
        return key
    }
    
    /// Retrieves the encryption key with the given `tag`.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to retrieve appropriate data, or if the data found with the given `tag` is not a valid key type.
    /// - returns: The key, or `nil` if no data exists in the keychain with the given `tag`.
    public func key<K: GenericPasswordConvertible>(withTag tag: String) throws -> K? {
        
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: tag,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        
        if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        
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
        
        let key = try K(rawRepresentation: keyData)
        // Store the context on if it exists.
        if let encKey = key as? EncryptionKey {
            encKey.context = item[kSecAttrAccount as String] as? String
        }
        
        return key
    }
    
    /// Returns `true` if a key exists and is accessible in the keychain with the given `tag`.
    ///
    /// This method is equivalent to calling `key(withTag: tag)` and checking for a
    /// nil value.
    public func keyExists<K: SecKeyConvertible>(ofType keyType: K.Type,
                                                withTag tag: String) -> Bool {
        return (try? key(withTag: tag)) as K? != nil
    }
    
    /// Returns `true` if a key exists and is accessible in the keychain with the given `tag`.
    ///
    /// This method is equivalent to calling `key(withTag: tag)` and checking for a
    /// nil value.
    public func keyExists<K: GenericPasswordConvertible>(ofType keyType: K.Type,
                                                         withTag tag: String) -> Bool {
        return (try? key(withTag: tag)) as K? != nil
    }
    
    /// Returns `true` if an `EncryptionKey` key exists and is accessible in the keychain with the given `tag`.
    @available(*, deprecated, message: "This method only checks for keys of type `EncryptionKey`. Use `keyExists(ofType:withTag:)` instead.")
    public func keyExists(withTag tag: String) -> Bool {
        return keyExists(ofType: EncryptionKey.self, withTag: tag)
    }
    
    public subscript<K: SecKeyConvertible>(_ tag: String) -> K? {
        get {
            return try? key(withTag: tag)
        }
        set(key) {
            if let newKey = key {
                _ = try? setKey(newKey, account: nil, forTag: tag)
            } else {
                _ = try? deleteKey(withTag: tag) as K?
            }
        }
    }
    
    public subscript<K: GenericPasswordConvertible>(_ tag: String) -> K? {
        get {
            return try? key(withTag: tag)
        }
        set(key) {
            if let newKey = key {
                _ = try? setKey(newKey, account: nil, forTag: tag)
            } else {
                _ = try? deleteKey(withTag: tag) as K?
            }
        }
    }
    
    public subscript(_ tag: String) -> EncryptionKey? {
        get {
            return try? key(withTag: tag)
        }
        set(key) {
            if let newKey = key {
                _ = try? setKey(newKey, forTag: tag)
            } else {
                _ = try? deleteKey(withTag: tag) as EncryptionKey?
            }
        }
    }
    
    // MARK: - Deleting Keys
    
    /// Deletes the data with the given `tag` from the keychain.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to delete the data with the given
    ///     `tag`.
    public func deleteKey(withTag tag: String) throws {
        _ = try deleteKey(withTag: tag) as AnySecKey?
        _ = try deleteKey(withTag: tag) as AnyGenericKey?
    }
    
    /// Deletes the data with the given `tag` from the keychain.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to delete the data with the given
    ///     `tag`.
    /// - returns: The key which was deleted, or `nil` if there was no data
    ///     with `tag`, or if that data wasn't the right type.
    public func deleteKey<K: SecKeyConvertible>(withTag tag: String) throws -> K? {
        
        // If this fails for bad data, we're deleting the data anyway.
        let existingKey: K? = try? key(withTag: tag)
        
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
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
    
    /// Deletes the data with the given `tag` from the keychain.
    ///
    /// - parameter tag: The identifier for some keychian data.
    /// - throws: A `StorageError` if the keychain fails to delete the data with the given
    ///     `tag`.
    /// - returns: The key which was deleted, or `nil` if there was no data
    ///     with `tag`, or if that data wasn't the right type.
    @discardableResult
    public func deleteKey<K: GenericPasswordConvertible>(withTag tag: String) throws -> K? {
        
        // If this fails for bad data, we're deleting the data anyway.
        let existingKey: K? = try? key(withTag: tag)
        
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
}

// MARK: - Errors

extension KeychainHandle {
    
    /// Indicates that a storage operation could not proceed.
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
    
    /// Converts the given `OSStatus` into a semantic `StorageError`, and throws it if
    /// appropriate.
    private func handleGenericError(status: OSStatus) throws {
        switch status {
        case errSecSuccess:      break
        case errSecAllocate:     throw StorageError.memoryError(reason: "Failed to allocate memory.")
        case errSecBadReq:       throw StorageError.badRequest
        case errSecDiskFull:     throw StorageError.diskFull
        case errSecDuplicateItem: throw StorageError.duplicateItem
        case errSecItemNotFound: throw StorageError.itemNotFound
        case errSecIO:           throw StorageError.ioError
        case errSecInvalidValue: throw StorageError.invalidValueDetected
        case errSecMemoryError:  throw StorageError.memoryError(reason: "A memory error occurred.")
        case errSecParam:        throw StorageError.invalidParameters
        case errSecUserCanceled: throw StorageError.cancelled
            
        default: // Throw the error
            let explanation: CFString
            if #available(iOS 11.3, *) {
                explanation = SecCopyErrorMessageString(status, nil) ?? "Unknown reason." as CFString
            } else {
                // Fallback on earlier versions
                explanation = "Unknown reason." as CFString
            }
            throw StorageError.unknown(reason: explanation as String)
        }
    }
    
}
