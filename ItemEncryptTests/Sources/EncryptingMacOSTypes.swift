//
//  EncryptingMacOSTypes.swift
//  ItemEncrypt-MacTests
//
//  Created by James Robinson on 5/23/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import XCTest
import ItemEncrypt

class EncryptingMacOSTypes: XCTestCase {
    
    var encryptor: EncryptionEncoder!
    var decryptor: EncryptionDecoder!
    
    let password = "password"
    var scheme: EncryptionSerialization.Scheme!
    var seed: [UInt8]!
    var iv: [UInt8]!
    var encKey: EncryptionKey!
    
    override func setUp() {
        encryptor = EncryptionEncoder()
        decryptor = EncryptionDecoder()
        scheme = .default
        seed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        iv = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        encKey = EncryptionKey(untreatedPassword: password, seed: seed, iv: iv, scheme: scheme)
    }

    override func tearDown() {
        encryptor = nil
        decryptor = nil
        scheme = nil
        seed = nil
        iv = nil
        encKey = nil
    }
    
    func testSmallImageEncryptionWithPassword() {
        
        let imageName = NSImage.Name("Scary Puppy") // ~150KB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        let encryptedItem = try! encryptor.encode(testData, withPassword: password)
        let encryptedPNG = NSImage(data: encryptedItem.rawData)
        XCTAssertNotEqual(encryptedPNG, testImage)
        
        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
        let decryptedImage = NSImage(data: decryptedPNG)
        XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
        
        do {
            let wrongPasswordPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: "this is wrong. :)")
            XCTFail("This shouldn't have decrypted at all.")
            let wrongPasswordImage = NSImage(data: wrongPasswordPNG)
            XCTAssert(wrongPasswordImage?.isPNGDataEqual(testImage) == false, "The image decrypted with the wrong password!")
            
        } catch {
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("Got some other error: \(error)")
                return
            }
        }
        
    }
    
    func testScreenshotEncryptionWithKey() {
        
        let imageName = NSImage.Name("Screenshot") // ~200KB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()
        
        let encryptedItem = try! encryptor.encode(testData, withKey: encKey)
        let encryptedPNG = NSImage(data: encryptedItem.rawData)
        XCTAssertNotEqual(encryptedPNG, testImage)
        
        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
        let decryptedImage = NSImage(data: decryptedPNG)
        XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
        
    }
    
    func testHugeImageEncryptionWithKey() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()
        
        let encryptedItem = try! encryptor.encode(testData, withKey: encKey)
        let encryptedPNG = NSImage(data: encryptedItem.rawData)
        XCTAssertNotEqual(encryptedPNG, testImage)
        
        let decryptedPNG = try! decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
        let decryptedImage = NSImage(data: decryptedPNG)
        XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
        
    }
    
    func testHugeImageEncryptionPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()
        
        measure {
            _ = try! encryptor.encode(testData, withKey: encKey)
        }
        
    }
    
    func testHugeImageDecryptionPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()
        
        let encryptedItem = try! encryptor.encode(testData, withKey: encKey)
        
        measure {
            _ = try! decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
        }
        
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
