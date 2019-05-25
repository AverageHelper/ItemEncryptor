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
    var scheme: EncryptionSerialization.Scheme!
    var seed: [UInt8]!
    var encKey: EncryptionKey!
    
    override func setUp() {
        encryptor = EncryptionEncoder()
        decryptor = EncryptionDecoder()
        scheme = .default
        seed = EncryptionSerialization.randomSalt(size: scheme.seedSize)
        encKey = EncryptionKey(untreatedPassword: password, seed: seed, scheme: scheme)
    }

    override func tearDown() {
        encryptor = nil
        decryptor = nil
        scheme = nil
        seed = nil
        encKey = nil
    }
    
    
    
    // MARK: - Basic password encryption
    
    func testStringEncryption() {
        // Basic test
        let normalString = "Hello, world!"
        let encryptedItem = try! encryptor.encode(normalString, withPassword: password)
        let encryptedString = String(data: encryptedItem.rawData, encoding: .utf8)
        XCTAssertNotEqual(normalString, encryptedString)
        
        let decryptedString = try! decryptor.decode(String.self, from: encryptedItem, withPassword: password)
        XCTAssertEqual(decryptedString, normalString)
        
        // Try an empty one
        
        let emptyString = ""
        let encryptedEmpty = try! encryptor.encode(emptyString, withPassword: password)
        let encryptedEmptyString = String(data: encryptedEmpty.rawData, encoding: .utf8)
        XCTAssertNotEqual(emptyString, encryptedEmptyString)
        
        let decryptedEmpty = try! decryptor.decode(String.self, from: encryptedEmpty, withPassword: password)
        XCTAssertEqual(decryptedEmpty, emptyString)
        
    }
    
    func testBooleanEncryption() {
        // True
        
        let testTrue = true
        let encryptedTrue = try! encryptor.encode(testTrue, withPassword: password)
        
        let decryptedBool = try! decryptor.decode(Bool.self, from: encryptedTrue, withPassword: password)
        XCTAssertEqual(decryptedBool, testTrue)
        
        // False
        
        let testFalse = false
        let encryptedFalse = try! encryptor.encode(testFalse, withPassword: password)
        
        let decryptedFalse = try! decryptor.decode(Bool.self, from: encryptedFalse, withPassword: password)
        XCTAssertEqual(decryptedFalse, testFalse)
        
    }
    
    func testIntegerEncryption() {
        // Positive
        
        let testPos: Int = 500_342
        let encPos = try! encryptor.encode(testPos, withKey: encKey)
        let decPos = try! decryptor.decode(Int.self, from: encPos, withKey: encKey)
        XCTAssertEqual(decPos, testPos)
        
        // With wrong password
        let wrongPasswordPos = try? decryptor.decode(Int.self, from: encPos, withPassword: "this is wrong")
        XCTAssertNotEqual(wrongPasswordPos, testPos)
        XCTAssertNil(wrongPasswordPos)
        
        // Negative
        
        let testNeg: Int = -451
        let encNeg = try! encryptor.encode(testNeg, withKey: encKey)
        let decNeg = try! decryptor.decode(Int.self, from: encNeg, withKey: encKey)
        XCTAssertEqual(decNeg, testNeg)
        
        // Zero
        
        let testZero: Int = 0
        let encZero = try! encryptor.encode(testZero, withKey: encKey)
        let decZero = try! decryptor.decode(Int.self, from: encZero, withKey: encKey)
        XCTAssertEqual(decZero, testZero)
        
        // Signed variants
        
        let testInt8: Int8 = Int8.random(in: Int8.min...Int8.max)
        let encInt8 = try! encryptor.encode(testInt8, withKey: encKey)
        let decInt8 = try! decryptor.decode(Int8.self, from: encInt8, withKey: encKey)
        XCTAssertEqual(decInt8, testInt8)
        
        let testInt16: Int16 = Int16.random(in: Int16.min...Int16.max)
        let encInt16 = try! encryptor.encode(testInt16, withKey: encKey)
        let decInt16 = try! decryptor.decode(Int16.self, from: encInt16, withKey: encKey)
        XCTAssertEqual(decInt16, testInt16)
        
        let testInt32: Int32 = Int32.random(in: Int32.min...Int32.max)
        let encInt32 = try! encryptor.encode(testInt32, withKey: encKey)
        let decInt32 = try! decryptor.decode(Int32.self, from: encInt32, withKey: encKey)
        XCTAssertEqual(decInt32, testInt32)
        
        let testInt64: Int64 = Int64.random(in: Int64.min...Int64.max)
        let encInt64 = try! encryptor.encode(testInt64, withKey: encKey)
        let decInt64 = try! decryptor.decode(Int64.self, from: encInt64, withKey: encKey)
        XCTAssertEqual(decInt64, testInt64)
        
        let wrongType = try? decryptor.decode(Int8.self, from: encInt64, withKey: encKey)
        XCTAssertNil(wrongType)
        
        // Unsigned variants
        
        let testUInt: UInt = UInt.random(in: UInt.min...UInt.max)
        let encUInt = try! encryptor.encode(testUInt, withKey: encKey)
        let decUInt = try! decryptor.decode(UInt.self, from: encUInt, withKey: encKey)
        XCTAssertEqual(decUInt, testUInt)
        
        let testUInt8: UInt8 = UInt8.random(in: UInt8.min...UInt8.max)
        let encUInt8 = try! encryptor.encode(testUInt8, withKey: encKey)
        let decUInt8 = try! decryptor.decode(UInt8.self, from: encUInt8, withKey: encKey)
        XCTAssertEqual(decUInt8, testUInt8)
        
        let testUInt16: UInt16 = UInt16.random(in: UInt16.min...UInt16.max)
        let encUInt16 = try! encryptor.encode(testUInt16, withKey: encKey)
        let decUInt16 = try! decryptor.decode(UInt16.self, from: encUInt16, withKey: encKey)
        XCTAssertEqual(decUInt16, testUInt16)
        
        let testUInt32: UInt32 = UInt32.random(in: UInt32.min...UInt32.max)
        let encUInt32 = try! encryptor.encode(testUInt32, withKey: encKey)
        let decUInt32 = try! decryptor.decode(UInt32.self, from: encUInt32, withKey: encKey)
        XCTAssertEqual(decUInt32, testUInt32)
        
        let testUInt64: UInt64 = UInt64.random(in: UInt64.min...UInt64.max)
        let encUInt64 = try! encryptor.encode(testUInt64, withKey: encKey)
        let decUInt64 = try! decryptor.decode(UInt64.self, from: encUInt64, withKey: encKey)
        XCTAssertEqual(decUInt64, testUInt64)
        
    }
    
    func testFloatEncryption() {
        
        // Finite
        
        let testPos: Float = 41.263451812345
        let encPos = try! encryptor.encode(testPos, withKey: encKey)
        let decPos = try! decryptor.decode(Float.self, from: encPos, withKey: encKey)
        XCTAssertEqual(decPos, testPos)
        
        let testNeg: Float = -32.34324523549
        let encNeg = try! encryptor.encode(testNeg, withKey: encKey)
        let decNeg = try! decryptor.decode(Float.self, from: encNeg, withKey: encKey)
        XCTAssertEqual(decNeg, testNeg)
        
        // Infinite
        
        let testInfinity: Float = Float.infinity
        let encInfinityFail = try? encryptor.encode(testInfinity, withKey: encKey)
        XCTAssertNil(encInfinityFail)
        
        encryptor.nonConformingFloatEncodingStrategy = .convertToString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
        let encInfinity = try! encryptor.encode(testInfinity, withKey: encKey)
        
        let decInfinityFail = try? decryptor.decode(Float.self, from: encInfinity, withKey: encKey)
        XCTAssertNil(decInfinityFail)
        
        decryptor.nonConformingFloatDecodingStrategy = .convertFromString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
        let decInfinity = try! decryptor.decode(Float.self, from: encInfinity, withKey: encKey)
        XCTAssertEqual(decInfinity, testInfinity)
        
        let testNegInfinity: Float = -Float.infinity
        let encNegInfinity = try! encryptor.encode(testNegInfinity, withKey: encKey)
        let decNegInfinity = try! decryptor.decode(Float.self, from: encNegInfinity, withKey: encKey)
        XCTAssertEqual(decNegInfinity, testNegInfinity)
        
        // Not a number
        
        let testNaN: Float = Float.nan
        let encNaN = try! encryptor.encode(testNaN, withKey: encKey)
        let decNaN = try! decryptor.decode(Float.self, from: encNaN, withKey: encKey)
        XCTAssert(decNaN.isNaN)
        
    }
    
    func testDoubleEncryption() {
        
        // Finite
        
        let testPos: Double = 41.263451812345
        let encPos = try! encryptor.encode(testPos, withKey: encKey)
        let decPos = try! decryptor.decode(Double.self, from: encPos, withKey: encKey)
        XCTAssertEqual(decPos, testPos)
        
        let testNeg: Double = -32.34324523549
        let encNeg = try! encryptor.encode(testNeg, withKey: encKey)
        let decNeg = try! decryptor.decode(Double.self, from: encNeg, withKey: encKey)
        XCTAssertEqual(decNeg, testNeg)
        
        // Infinite
        
        let testInfinity: Double = Double.infinity
        let encInfinityFail = try? encryptor.encode(testInfinity, withKey: encKey)
        XCTAssertNil(encInfinityFail)
        
        encryptor.nonConformingFloatEncodingStrategy = .convertToString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
        let encInfinity = try! encryptor.encode(testInfinity, withKey: encKey)
        
        let decInfinityFail = try? decryptor.decode(Double.self, from: encInfinity, withKey: encKey)
        XCTAssertNil(decInfinityFail)
        
        decryptor.nonConformingFloatDecodingStrategy = .convertFromString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
        let decInfinity = try! decryptor.decode(Double.self, from: encInfinity, withKey: encKey)
        XCTAssertEqual(decInfinity, testInfinity)
        
        let testNegInfinity: Double = -Double.infinity
        let encNegInfinity = try! encryptor.encode(testNegInfinity, withKey: encKey)
        let decNegInfinity = try! decryptor.decode(Double.self, from: encNegInfinity, withKey: encKey)
        XCTAssertEqual(decNegInfinity, testNegInfinity)
        
        // Not a number
        
        let testNaN: Double = Double.nan
        let encNaN = try! encryptor.encode(testNaN, withKey: encKey)
        let decNaN = try! decryptor.decode(Double.self, from: encNaN, withKey: encKey)
        XCTAssert(decNaN.isNaN)
        
    }
    
    func testDateEncryption() {
        
        let testNow = Date()
        let encNow = try! encryptor.encode(testNow, withKey: encKey)
        let decNow = try! decryptor.decode(Date.self, from: encNow, withKey: encKey)
        XCTAssertEqual(decNow, testNow)
        
        let testDistantFuture = Date.distantFuture
        let encFuture = try! encryptor.encode(testDistantFuture, withKey: encKey)
        let decFuture = try! decryptor.decode(Date.self, from: encFuture, withKey: encKey)
        XCTAssertEqual(decFuture, testDistantFuture)
        
        let testDistantPast = Date.distantPast
        let encPast = try! encryptor.encode(testDistantPast, withKey: encKey)
        let decPast = try! decryptor.decode(Date.self, from: encPast, withKey: encKey)
        XCTAssertEqual(decPast, testDistantPast)
        
        // ISO-8601
        
        let isoDate = Date()
        
        encryptor.dateEncodingStrategy = .iso8601
        decryptor.dateDecodingStrategy = .iso8601
        let encIsoDate = try! encryptor.encode(isoDate, withKey: encKey)
        let decIsoDate = try! decryptor.decode(Date.self, from: encIsoDate, withKey: encKey)
        // We cannot guarantee exact equality here, so we compare the integer of their reference intervals.
        XCTAssertEqual(Int(decIsoDate.timeIntervalSinceReferenceDate),
                       Int(isoDate.timeIntervalSinceReferenceDate))
        
    }
    
    func testNilEncryption() {
        do {
            let _ = try encryptor.encode(NullValue(), withPassword: password)
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    
    
    // MARK: - Encrypted Item
    
    func testEncryptedDataParse() {
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
    
    func testEncryptedItemFromBogusData() {
        let randomData = Data(repeating: UInt8.random(in: 0...9), count: 16)
        
        do {
            let item = try EncryptedItem(data: randomData, usingConfiguration: .default)
            XCTFail("Random data shouldn't create an EncryptedItem: \(item.rawData)")
            
        } catch {
            XCTAssert(error is EncryptionSerialization.DecryptionError, "Got a different error: \(error)")
        }
        
    }
    
    
    // MARK: - Encryption Keys
    
    func testEncryptionKeyDerivation() {
        let userId = "thisIsMyUserID1234"
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomSalt(size: scheme.seedSize)
        let newTestKey = EncryptionKey(untreatedPassword: password,
                                       additionalData: [userId],
                                       seed: randomSeed,
                                       scheme: scheme)
        // Store the salt for later...
        let storedSalt = newTestKey.salt
        
        let derivedKey = EncryptionKey(untreatedPassword: password,
                                       treatedSalt: storedSalt,
                                       scheme: scheme)
        XCTAssertEqual(derivedKey, newTestKey)
        
    }
    
    func testSetOfKeys() {
        var randomSeed: [UInt8] { return EncryptionSerialization.randomSalt(size: 16) }
        let key1 = EncryptionKey(untreatedPassword: password, seed: randomSeed, scheme: .default)
        let key2 = EncryptionKey(untreatedPassword: password, seed: randomSeed, scheme: .default)
        let key3 = EncryptionKey(untreatedPassword: password, seed: randomSeed, scheme: .default)
        
        var keySet = Set<EncryptionKey>()
        keySet.insert(key1)
        keySet.insert(key2)
        keySet.insert(key3)
        keySet.insert(key1)
        XCTAssertEqual(keySet.count, 3)
        
    }
    
    
    
    // MARK - Performance
    
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
    
    func testEncryptionPerformanceWithKey() {
        let testString = "Lorem ipsum dolor sit amet"
        
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomSalt(size: scheme.seedSize)
        let encKey = EncryptionKey(untreatedPassword: password, seed: randomSeed, scheme: scheme)
        
        measure {
            let _ = try! encryptor.encode(testString, withKey: encKey)
        }
        
    }
    
    func testDecryptionPerformanceWithKey() {
        let testString = "Lorem ipsum dolor sit amet"
        
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomSalt(size: scheme.seedSize)
        let encKey = EncryptionKey(untreatedPassword: password, seed: randomSeed, scheme: scheme)
        let encryptedString = try! encryptor.encode(testString, withKey: encKey)
        
        measure {
            let _ = try! decryptor.decode(String.self, from: encryptedString, withKey: encKey)
        }
        
    }
    
}



struct NullValue: Codable {
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encodeNil()
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        _ = container.decodeNil()
    }
    
    init() {}
    
}