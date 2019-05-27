//
//  ItemEncryptTests.swift
//  ItemEncryptTests
//
//  Created by James Robinson on 5/13/19.
//  Copyright © 2019 LeadDevCreations, LLC. All rights reserved.
//

import XCTest
import ItemEncrypt

class EncryptingiOSTypes: XCTestCase {
    
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
        
        let imageName = "Scary Puppy" // ~150KB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        XCTAssertFalse(UIImage(data: testData)!.isEqual(testImage), "Hello! .isEqual(_:) seems to work for parsing PNG data now! Investigate this.")
        
        let encryptedItem: EncryptedItem
        do {
            encryptedItem = try encryptor.encode(testData, withPassword: password)
            let encryptedPNG = UIImage(data: encryptedItem.rawData)
            
            XCTAssertNotEqual(testImage, encryptedPNG)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: password)
            let decryptedImage = UIImage(data: decryptedPNG)
            XCTAssertNotNil(decryptedImage)
            XCTAssert(decryptedImage!.isPNGDataEqual(testImage), "The decrypted image is not the same as the original.")
            
        } catch {
            XCTFail("\(error)")
            return
        }
        
        do {
            let wrongPasswordPNG = try decryptor.decode(Data.self, from: encryptedItem, withPassword: "this is wrong. :)")
            XCTFail("This shouldn't have decrypted at all.")
            let wrongPasswordImage = UIImage(data: wrongPasswordPNG)
            XCTAssert(wrongPasswordImage?.isPNGDataEqual(testImage) == false, "The image decrypted with the wrong password!")
            
        } catch {
            guard case DecodingError.dataCorrupted = error else {
                XCTFail("\(error)")
                return
            }
        }
    }
    
    func testScreenshotEncryptionWithKey() {
        
        let imageName = "Screenshot" // ~200KB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        do {
            let encryptedItem = try encryptor.encode(testData, withKey: encKey)
            let encryptedPNG = UIImage(data: encryptedItem.rawData)
            XCTAssertNotEqual(encryptedPNG, testImage)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
            let decryptedImage = UIImage(data: decryptedPNG)
            XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testHugeImageEncryptionWithKey() {
        
        let imageName = "Receipt" // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        do {
            let encryptedItem = try encryptor.encode(testData, withKey: encKey)
            let encryptedPNG = UIImage(data: encryptedItem.rawData)
            XCTAssertNotEqual(encryptedPNG, testImage)
            
            let decryptedPNG = try decryptor.decode(Data.self, from: encryptedItem, withKey: encKey)
            let decryptedImage = UIImage(data: decryptedPNG)
            XCTAssert(decryptedImage?.isPNGDataEqual(testImage) == true)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testHugeImageEncryptionPerformance() {
        
        let imageName = "Receipt" // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        measure {
            do {
                _ = try encryptor.encode(testData, withKey: encKey)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testHugeImageDecryptionPerformance() {
        
        let imageName = "Receipt" // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
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
        
        let imageName = "Receipt" // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
        measureMetrics([.wallClockTime], automaticallyStartMeasuring: false) {
            let encInput = InputStream(data: testData)
            let encOutput = OutputStream(toMemory: ())
            startMeasuring()
            EncryptionSerialization.encryptDataStream(encInput, withKey: encKey, into: encOutput)
            stopMeasuring()
        }
        
    }
    
    func testHugeImageDecryptionStreamPerformance() {
        
        let imageName = "Receipt" // ~16MB
        let bundle = Bundle(for: type(of: self))
        let testImage = UIImage(named: imageName, in: bundle, compatibleWith: nil)!
        let testData = testImage.pngData()!
        
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
