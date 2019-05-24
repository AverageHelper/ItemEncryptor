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
    
    func isPNGDataEqual(_ other: NSImage?) -> Bool {
        guard let otherImage = other else {
            return false
        }
        
        let selfPNG = self.pngRepresentation()
        let otherPNG = otherImage.pngRepresentation()
        
        return selfPNG == otherPNG
    }

}
