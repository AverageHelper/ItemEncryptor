//
//  EncryptedItem.swift
//  ItemEncrypt
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import Foundation

public struct EncryptedItem {
    // MARK: Options
    
    public enum Format {
        /// The first version of our encrypted data format.
        case pilot
        
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
    
    internal let version: Format
    internal let payload: Data
    internal let salt: [UInt8]
    
    public var rawData: Data {
        return version.rawValue + payload + salt
    }
    
    // MARK: - Constructing an Encrypted Item
    
    internal init(version: Format = .pilot, payload: Data, salt: [UInt8]) {
        self.version = version
        self.payload = payload
        self.salt = salt
    }
    
    /// Attempts to derive an `EncryptedItem` from given `data` using the given `configuration`
    ///   options. If the spec version is found not to match the configuration's
    ///   version spec, an error is thrown.
    internal init(data: Data, usingConfiguration configuration: EncryptionSerialization.Specification) throws {
        
        // Configuration tells us how to look at this data.
        var resultPayload = Data()
        var resultSalt = [UInt8]()
        try EncryptedItem.parseData(data,
                                    into: &resultPayload,
                                    resultSalt: &resultSalt,
                                    version: configuration.version,
                                    saltSize: configuration.saltSize)
        
        self.version = configuration.version
        self.payload = resultPayload
        self.salt = resultSalt
    }
    
    /// Attempts to parse given data into semantic version format ID, salt, and payload blocks.
    private static func parseData(_ data: Data,
                                  into resultPayload: inout Data,
                                  resultSalt: inout [UInt8],
                                  version: Format,
                                  saltSize expectedSaltSize: Int) throws {
        
        // version + payload + salt
        var mutableData = data
        
        let expectedVersionSize = version.rawValue.count
        let expectedVersionData = mutableData[mutableData.startIndex..<expectedVersionSize]
        guard let foundVersion = Format(bytes: [UInt8](expectedVersionData)) else {
            throw EncryptionSerialization.DecryptionError.badData
        }
        guard foundVersion == version else {
            throw EncryptionSerialization.DecryptionError.incorrectVersion
        }
        
        mutableData = mutableData.subdata(in: (expectedVersionSize - 1)..<mutableData.endIndex)
        
        let saltStart = data.endIndex.advanced(by: -expectedSaltSize)
        let expectedSaltData = data[saltStart..<data.count]
        let proposedSalt = [UInt8](expectedSaltData)
        resultSalt = proposedSalt
        
        mutableData = mutableData.subdata(in: mutableData.startIndex..<saltStart)
        resultPayload = mutableData
    }
    
}
