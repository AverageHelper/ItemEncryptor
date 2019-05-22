//
//  ItemEncryptTests.swift
//  ItemEncryptTests
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import XCTest
@testable import ItemEncrypt

class ItemEncryptTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testStringEncryption() {
        let encryptor = EncryptingEncoder()
        
        let password = "password"
        let testString = "Hello, world!"
        
        let encryptedItem = try! encryptor.encode(testString, withPassword: password)
        let encryptedString = String(data: encryptedItem.rawData, encoding: .utf8)
        XCTAssertNotEqual(testString, encryptedString)
        
        let decryptor = EncryptingDecoder()
        let decryptedString = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(decryptedString, testString)
    }
    
}
