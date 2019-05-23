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
    
    func testImageEncryption() {
        
        let password = "password"
        
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: "Scary Puppy", in: bundle, compatibleWith: nil)
        let testData = testImage!.pngData()!
        
        if #available(OSX 10.0, *) {
//            let imageName = NSImage.Name("Scary Puppy")
//            let bundle = Bundle(for: type(of: self))
//            let testImagePath = bundle.pathForImageResource(imageName)!
//            let testImage = NSImage(contentsOfFile: testImagePath)!
//            testData = testImage.pngRepresentation()!
        }
        
        let encryptor = EncryptionEncoder()
        
        let encryptedItem = try! encryptor.encode(testData, withPassword: password)
        let encryptedPNG = UIImage(data: encryptedItem.rawData)

        XCTAssertNotEqual(testImage, encryptedPNG)

        let decryptor = EncryptionDecoder()
        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
        let decryptedImage = UIImage(data: decryptedPNG)
        XCTAssertEqual(decryptedImage, testImage)
    }
    
}

extension UIImage {
    
    open override func isEqual(_ object: Any?) -> Bool {
        guard let otherImage = object as? UIImage else {
            return false
        }
        
        let selfPNG = self.pngData()
        let otherPNG = otherImage.pngData()
        
        return selfPNG == otherPNG
    }
    
}
