//
//  EncryptingMacOSTypes.swift
//  ItemEncrypt-MacTests
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import XCTest
@testable import ItemEncrypt

class EncryptingMacOSTypes: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testImageEncryption() {
        
        let password = "password"
        
        let imageName = NSImage.Name("Scary Puppy")
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        let encryptor = EncryptionEncoder()
        
        let encryptedItem = try! encryptor.encode(testData, withPassword: password)
        let encryptedPNG = NSImage(data: encryptedItem.rawData)
        
        XCTAssertNotEqual(testImage, encryptedPNG)
        
        let decryptor = EncryptionDecoder()
        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
        let decryptedImage = NSImage(data: decryptedPNG)
        XCTAssertEqual(decryptedImage, testImage)
    }

}

extension NSImage {

    func pngRepresentation() -> Data? {
        guard let imageData = self.tiffRepresentation else { return nil }
        let imageRep = NSBitmapImageRep(data: imageData)
        let imageProps = [NSBitmapImageRep.PropertyKey.compressionFactor: 1.0]
        return imageRep?.representation(using: .png, properties: imageProps)
    }
    
    open override func isEqual(_ object: Any?) -> Bool {
        guard let otherImage = object as? NSImage else {
            return false
        }
        
        let selfPNG = self.pngRepresentation()
        let otherPNG = otherImage.pngRepresentation()
        
        return selfPNG == otherPNG
    }

}
