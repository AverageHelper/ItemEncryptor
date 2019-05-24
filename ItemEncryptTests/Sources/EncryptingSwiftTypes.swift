//
//  EncryptingSwiftTypes.swift
//  ItemEncrypt-MacTests
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import XCTest
@testable import ItemEncrypt

class EncryptingSwiftTypes: XCTestCase {
    
    var encryptor: EncryptionEncoder!
    var decryptor: EncryptionDecoder!
    let password = "password"
    
    override func setUp() {
        encryptor = EncryptionEncoder()
        decryptor = EncryptionDecoder()
    }

    override func tearDown() {
        encryptor = nil
        decryptor = nil
    }
    
    func testStringEncryption() {
        let testString = "Hello, world!"
        
        let encryptedItem = try! encryptor.encode(testString, withPassword: password)
        let encryptedString = String(data: encryptedItem.rawData, encoding: .utf8)
        XCTAssertNotEqual(testString, encryptedString)
        
        let decryptedString = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(decryptedString, testString)
    }
    
    func testBooleanEncryption() {
        let testTrue = true
        
        let encryptedTrue = try! encryptor.encode(testTrue, withPassword: password)
        let decryptedBool = try! decryptor.decode(Bool.self, from: encryptedTrue, withPassword: password)
        XCTAssertEqual(decryptedBool, testTrue)
        
        let testFalse = false
        
        let encryptedFalse = try! encryptor.encode(testFalse, withPassword: password)
        let decryptedFalse = try! decryptor.decode(Bool.self, from: encryptedFalse, withPassword: password)
        XCTAssertEqual(decryptedFalse, testFalse)
    }
    
    func testEncryptedItemCreateFromRawDataProp() {
        let testText = "Lorem ipsum dolor sit amet"
        
        let encryptedItem = try! encryptor.encode(testText, withPassword: password)
        let testDecryptedString = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(testDecryptedString, testText)
        
        let encryptedData = encryptedItem.rawData
        
        do {
            let newItem = try EncryptedItem(data: encryptedData, usingConfiguration: .default)
            XCTAssertEqual(newItem, encryptedItem)
            XCTAssertEqual(newItem.rawData, encryptedData)
            
            do {
                let decryptedString = try decryptor.decode(String.self, from: newItem, withPassword: password)
                XCTAssertEqual(decryptedString, testText)
                
            } catch {
                XCTFail("Failed to decrypt: \(error)")
            }
            
        } catch {
            XCTFail("Failed to create EncryptedItem: \(error)")
        }
    }
    
    func testEncryptedItemCreateBogusData() {
        let randomData = Data(repeating: UInt8.random(in: 0...9), count: 16)
        
        do {
            let item = try EncryptedItem(data: randomData, usingConfiguration: .default)
            XCTFail("Random data shouldn't create an EncryptedItem: \(item.rawData)")
            
        } catch {
            XCTAssert(error is EncryptionSerialization.DecryptionError, "Got a different error: \(error)")
        }
        
    }
    
    func testIntegerEncryption() {
        let testInt = 500_342
        
        let encryptedItem = try! encryptor.encode(testInt, withPassword: password)
        let decryptedInt = try! decryptor.decode(Int.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(decryptedInt, testInt)
        
        let wrongPasswordInt = try? decryptor.decode(Int.self, from: encryptedItem, withPassword: "this is wrong")
        XCTAssertNotEqual(wrongPasswordInt, testInt)
    }
    
    func testEncryptionPerformance() {
        let testString = "Lorem ipsum dolor sit amet"
        
        measure {
            let _ = try! encryptor.encode(testString, withPassword: password)
        }
    }
    
    func testDecryptionPerformance() {
        let testString = "Lorem ipsum dolor sit amet"
        let encryptedItem = try! encryptor.encode(testString, withPassword: password)
        
        measure {
            let _ = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        }
    }
    
}
