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
        encKey = try! EncryptionKey(untreatedPassword: password, seed: seed, iv: iv, scheme: scheme)
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
        
        let encryptedItem: EncryptedItem
        do {
            encryptedItem = try encryptor.encode(testData, withPassword: password)
            let encryptedPNG = NSImage(data: encryptedItem.rawData)
            XCTAssertNotEqual(encryptedPNG, testImage)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
            let decryptedImage = NSImage(data: decryptedPNG)
            XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
            
        } catch {
            XCTFail("\(error)")
            return
        }
        
        do {
            let wrongPasswordPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: "this is wrong. :)")
            XCTFail("This shouldn't have decrypted at all.")
            let wrongPasswordImage = NSImage(data: wrongPasswordPNG)
            XCTAssert(wrongPasswordImage?.isPNGDataEqual(testImage) == false, "The image decrypted with the wrong password!")
            
        } catch {
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("\(error)")
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
        
        do {
            let encryptedItem = try encryptor.encode(testData, withKey: encKey)
            let encryptedPNG = NSImage(data: encryptedItem.rawData)
            XCTAssertNotEqual(encryptedPNG, testImage)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
            let decryptedImage = NSImage(data: decryptedPNG)
            XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testHugeImageEncryptionWithKey() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()
        
        do {
            let encryptedItem = try encryptor.encode(testData, withKey: encKey)
            let encryptedPNG = NSImage(data: encryptedItem.rawData)
            XCTAssertNotEqual(encryptedPNG, testImage)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
            let decryptedImage = NSImage(data: decryptedPNG)
            XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testHugeImageStreamEncryption() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        let encInput = InputStream(data: testData)
        let encOutput = OutputStream(toMemory: ())
        EncryptionSerialization.encryptDataStream(encInput, withKey: encKey, into: encOutput)
        
        let encryptedData = encOutput.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        let decInput = InputStream(data: encryptedData)
        let decOutput = OutputStream(toMemory: ())
        EncryptionSerialization.decryptDataStream(decInput, withKey: encKey, into: decOutput)
        
        let decryptedData = decOutput.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssertEqual(decryptedData, testData)
        let decryptedImage = NSImage(data: decryptedData)
        XCTAssert(decryptedImage?.pngRepresentation() == testImage.pngRepresentation())
    }
    
    func testHugeImageEncryptionPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        measure {
            do {
                _ = try encryptor.encode(testData, withKey: encKey)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testHugeImageDecryptionPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        let encryptedItem: EncryptedItem
        do {
            encryptedItem = try encryptor.encode(testData, withKey: encKey)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testHugeImageEncryptionStreamPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        measureMetrics([.wallClockTime], automaticallyStartMeasuring: false) {
            let encInput = InputStream(data: testData)
            let encOutput = OutputStream(toMemory: ())
            startMeasuring()
            EncryptionSerialization.encryptDataStream(encInput, withKey: encKey, into: encOutput)
            stopMeasuring()
        }
        
    }
    
    func testHugeImageDecryptionStreamPerformance() {
        
        let imageName = NSImage.Name("Receipt") // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImagePath = bundle.pathForImageResource(imageName)!
        let testImage = NSImage(contentsOfFile: testImagePath)!
        let testData = testImage.pngRepresentation()!
        
        let encInput = InputStream(data: testData)
        let encOutput = OutputStream(toMemory: ())
        EncryptionSerialization.encryptDataStream(encInput, withKey: encKey, into: encOutput)
        
        let encryptedData = encOutput.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        measureMetrics([.wallClockTime], automaticallyStartMeasuring: false) {
            let decInput = InputStream(data: encryptedData)
            let decOutput = OutputStream(toMemory: ())
            startMeasuring()
            EncryptionSerialization.decryptDataStream(decInput, withKey: encKey, into: decOutput)
            stopMeasuring()
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
