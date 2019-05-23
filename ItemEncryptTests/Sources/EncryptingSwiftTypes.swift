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

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testStringEncryption() {
        
        let password = "password"
        let testString = "Hello, world!"
        
        let encryptor = EncryptionEncoder()
        
        let encryptedItem = try! encryptor.encode(testString, withPassword: password)
        let encryptedString = String(data: encryptedItem.rawData, encoding: .utf8)
        XCTAssertNotEqual(testString, encryptedString)
        
        let decryptor = EncryptionDecoder()
        let decryptedString = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(decryptedString, testString)
    }

}
