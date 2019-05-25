//
//  EncryptedItem.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation

public struct EncryptedItem: Equatable, Hashable {
    // MARK: Properties
    
    internal let version: EncryptionSerialization.Scheme.Format
    internal let payload: Data
    internal let salt: [UInt8]
    
    public var rawData: Data {
        var res = version.rawValue
        res.append(contentsOf: payload)
        res.append(contentsOf: salt)
        
        return Data(res)
    }
    
    // MARK: - Constructing an Encrypted Item
    
    internal init(version: EncryptionSerialization.Scheme.Format,
                  payload: Data,
                  salt: [UInt8]) {
        self.version = version
        self.payload = payload
        self.salt = salt
    }
    
    /// Attempts to derive an `EncryptedItem` from given `data` using the given `configuration`
    ///   options. If the spec version is found not to match the configuration's
    ///   version spec, an error is thrown.
    public init(data: Data, usingConfiguration configuration: EncryptionSerialization.Scheme) throws {
        
        // Configuration tells us how to look at this data.
        var resultPayload = Data()
        var resultSalt = [UInt8]()
        try EncryptedItem.parseData(data,
                                    into: &resultPayload,
                                    resultSalt: &resultSalt,
                                    version: configuration.version,
                                    saltSize: configuration.stretchedSaltSize)
        
        self.version = configuration.version
        self.payload = resultPayload
        self.salt = resultSalt
    }
    
    /// Attempts to parse given data into semantic version format ID, salt, and payload blocks.
    private static func parseData(_ data: Data,
                                  into resultPayload: inout Data,
                                  resultSalt: inout [UInt8],
                                  version: EncryptionSerialization.Scheme.Format,
                                  saltSize expectedSaltSize: Int) throws {
        
        // version + payload + salt
        var mutableData = data
        
        let expectedVersionSize = version.rawValue.count
        let expectedVersionData = mutableData[mutableData.startIndex..<expectedVersionSize]
        guard let foundVersion =
            EncryptionSerialization.Scheme.Format(bytes: [UInt8](expectedVersionData)) else {
            throw EncryptionSerialization.DecryptionError.badData
        }
        guard foundVersion == version else {
            throw EncryptionSerialization.DecryptionError.incorrectVersion
        }
        
        // Slice off our version data
        mutableData = mutableData.subdata(in: expectedVersionSize..<mutableData.endIndex)
        
        let saltStart = mutableData.endIndex.advanced(by: -expectedSaltSize)
        let expectedSaltData = mutableData[saltStart..<mutableData.count]
        let proposedSalt = [UInt8](expectedSaltData)
        resultSalt = proposedSalt
        
        // Slice off our salt
        mutableData = mutableData.subdata(in: mutableData.startIndex..<saltStart)
        resultPayload = mutableData
    }
    
}

extension EncryptedItem {
    
    public static func == (lhs: EncryptedItem, rhs: EncryptedItem) -> Bool {
        return lhs.rawData == rhs.rawData
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawData)
    }
    
}
