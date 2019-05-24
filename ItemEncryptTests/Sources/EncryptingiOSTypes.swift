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
    
    func testImageEncryption() {
        
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: "Scary Puppy", in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        XCTAssertFalse(UIImage(data: testData)!.isEqual(testImage), "Hello! .isEqual(_:) seems to work for parsing PNG data now! Investigate this.")
        
        let encryptedItem = try! encryptor.encode(testData, withPassword: password)
        let encryptedPNG = UIImage(data: encryptedItem.rawData)

        XCTAssertNotEqual(testImage, encryptedPNG)

        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
        let decryptedImage = UIImage(data: decryptedPNG)
        XCTAssertNotNil(decryptedImage)
        XCTAssert(decryptedImage!.isPNGDataEqual(testImage), "The decrypted image is not the same as the original.")
        
        do {
            let wrongPasswordPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: "this is wrong. :)")
            XCTFail("This shouldn't have decrypted at all.")
            let wrongPasswordImage = UIImage(data: wrongPasswordPNG)
            XCTAssert(wrongPasswordImage?.isPNGDataEqual(testImage) == false, "The image decrypted with the wrong password!")
            
        } catch {
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Got some other error: \(error)")
                return
            }
        }
    }
    
}

extension UIImage {
    
    func isPNGDataEqual(_ other: UIImage?) -> Bool {
        guard let otherImage = other else {
            return false
        }
        
        let selfPNG = self.pngData()
        let otherPNG = otherImage.pngData()
        
        return selfPNG == otherPNG
    }

}
