//
//  EncryptingSwiftTypes.swift
//  ItemEncrypt-MacTests
//
//  Created on 5/23/19.
//

import XCTest
import ItemEncrypt

final class EncryptingSwiftTypes: XCTestCase {
    
    var encryptor: EncryptionEncoder!
    var decryptor: EncryptionDecoder!
    
    let password = "password"
    var schemeV1: EncryptionSerialization.Scheme!
    var schemeV2: EncryptionSerialization.Scheme?
    var seed: [UInt8]!
    var iv: EncryptedItem.IV!
    var encKeyV1: EncryptionKey!
    var encKeyV2: EncryptionKey?
    
    override func setUp() {
        encryptor = EncryptionEncoder()
        decryptor = EncryptionDecoder()
        schemeV1 = .init(format: .version1)
        seed = EncryptionSerialization.randomBytes(count: schemeV1.seedSize)
        iv = EncryptionSerialization.randomBytes(count: schemeV1.initializationVectorSize)
        
        encKeyV1 = try! EncryptionKey(untreatedPassword: password, seed: seed, iv: iv, scheme: schemeV1)
        encKeyV1.context = "For testing version 1"
        
        if #available(iOS 13.0, OSX 10.15, watchOS 6.0, tvOS 13.0, *) {
            schemeV2 = .init(format: .version2)
            encKeyV2 = try! EncryptionKey(untreatedPassword: password, seed: seed, iv: iv, scheme: schemeV2!)
            encKeyV2!.context = "For testing version 2"
        }
    }
    
    override func tearDown() {
        encryptor = nil
        decryptor = nil
        schemeV1 = nil
        schemeV2 = nil
        seed = nil
        iv = nil
        encKeyV1 = nil
        encKeyV2 = nil
    }
    
    
    
    // MARK: - Basic password encryption
    
    func testStringEncryption() {
        // Basic test
        let normalString = "Hello, world!"
        let encryptedItem: EncryptedItem
        do {
            encryptedItem = try encryptor.encode(normalString, withPassword: password)
            let encryptedString = String(data: encryptedItem.rawData, encoding: .utf8)
            XCTAssertNotEqual(normalString, encryptedString)
            
        } catch {
            XCTFail("\(error)")
            return
        }
        
        do {
            let decryptedString = try decryptor.decode(String.self, from: encryptedItem, withPassword: password)
            XCTAssertEqual(decryptedString, normalString)
            
        } catch {
            XCTFail("\(error)")
            return
        }
        
        // Try an empty one
        
        let emptyString = ""
        let encryptedEmpty: EncryptedItem
        do {
            encryptedEmpty = try encryptor.encode(emptyString, withPassword: password)
            
        } catch {
            XCTFail("\(error)")
            return
        }
        let encryptedEmptyString = String(data: encryptedEmpty.rawData, encoding: .utf8)
        XCTAssertNotEqual(emptyString, encryptedEmptyString)
        
        do {
            let decryptedEmpty = try decryptor.decode(String.self,
                                                      from: encryptedEmpty,
                                                      withPassword: password)
            XCTAssertEqual(decryptedEmpty, emptyString)
        } catch {
            XCTFail("\(error)")
        }
        
        // Version 2 Encrypt/Decrypt
        // Version 1 and 2 should be interchangeable
        
        guard let encKeyV2 = self.encKeyV2 else { return }
        
        let someString = normalString
        var encryptedString = try! encryptor.encode(someString, withKey: encKeyV2)
        let encryptedStringValue = String(data: encryptedString.rawData, encoding: .utf8)
        XCTAssertNotEqual(someString, encryptedStringValue)
        do {
            let decryptedString = try decryptor.decode(String.self, from: encryptedString, withKey: encKeyV2)
            XCTAssertEqual(decryptedString, someString)
        } catch {
            XCTFail("\(error)")
        }
        // V1 keys should be compatible with V2 data, since we used the same salt and IV.
        do {
            let usedOldKey = try decryptor.decode(String.self, from: encryptedString, withKey: encKeyV1)
            XCTAssertEqual(usedOldKey, someString, "Decryption results differ.")
        } catch {
            XCTFail("\(error)")
        }
        
        encryptedString = try! encryptor.encode(someString, withKey: encKeyV1)
        do {
            let usedNewKey = try decryptor.decode(String.self, from: encryptedString, withKey: encKeyV2)
            XCTAssertEqual(usedNewKey, someString, "Decryption results differ.")
//            XCTFail("New key should not work on old data.")
            
//        } catch let err as EncryptionSerialization.DecryptionError {
//            guard case .badData = err else {
//                return XCTFail("\(err)")
//            }
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testBooleanEncryption() {
        // True
        
        let testTrue = true
        do {
            let encryptedTrue = try encryptor.encode(testTrue, withPassword: password)
            
            let decryptedBool = try decryptor.decode(Bool.self, from: encryptedTrue, withPassword: password)
            XCTAssertEqual(decryptedBool, testTrue)
        } catch {
            XCTFail("\(error)")
        }
        
        // False
        
        let testFalse = false
        do {
            let encryptedFalse = try encryptor.encode(testFalse, withPassword: password)
            
            let decryptedFalse = try decryptor.decode(Bool.self, from: encryptedFalse, withPassword: password)
            XCTAssertEqual(decryptedFalse, testFalse)
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testIntegerEncryption() {
        
        do {
            // Positive
            
            let testPos: Int = 500_342
            let encPos = try encryptor.encode(testPos, withKey: encKeyV1)
            let decPos = try decryptor.decode(Int.self, from: encPos, withKey: encKeyV1)
            XCTAssertEqual(decPos, testPos)
            
            // With wrong password, should throw.
            let wrongPasswordPos = try? decryptor.decode(Int.self, from: encPos, withPassword: "this is wrong")
            XCTAssertNotEqual(wrongPasswordPos, testPos)
            XCTAssertNil(wrongPasswordPos)
            
            // Negative
            
            let testNeg: Int = -451
            let encNeg = try encryptor.encode(testNeg, withKey: encKeyV1)
            let decNeg = try decryptor.decode(Int.self, from: encNeg, withKey: encKeyV1)
            XCTAssertEqual(decNeg, testNeg)
            
            // Zero
            
            let testZero: Int = 0
            let encZero = try encryptor.encode(testZero, withKey: encKeyV1)
            let decZero = try decryptor.decode(Int.self, from: encZero, withKey: encKeyV1)
            XCTAssertEqual(decZero, testZero)
            
            // Signed variants
            
            let testInt8: Int8 = Int8.random(in: Int8.min...Int8.max)
            let encInt8 = try encryptor.encode(testInt8, withKey: encKeyV1)
            let decInt8 = try decryptor.decode(Int8.self, from: encInt8, withKey: encKeyV1)
            XCTAssertEqual(decInt8, testInt8)
            
            let testInt16: Int16 = Int16.random(in: Int16.min...Int16.max)
            let encInt16 = try encryptor.encode(testInt16, withKey: encKeyV1)
            let decInt16 = try decryptor.decode(Int16.self, from: encInt16, withKey: encKeyV1)
            XCTAssertEqual(decInt16, testInt16)
            
            let testInt32: Int32 = Int32.random(in: Int32.min...Int32.max)
            let encInt32 = try encryptor.encode(testInt32, withKey: encKeyV1)
            let decInt32 = try decryptor.decode(Int32.self, from: encInt32, withKey: encKeyV1)
            XCTAssertEqual(decInt32, testInt32)
            
            let testInt64: Int64 = Int64.random(in: Int64.min...Int64.max)
            let encInt64 = try encryptor.encode(testInt64, withKey: encKeyV1)
            let decInt64 = try decryptor.decode(Int64.self, from: encInt64, withKey: encKeyV1)
            XCTAssertEqual(decInt64, testInt64)
            
            let wrongType = try? decryptor.decode(Int8.self, from: encInt64, withKey: encKeyV1)
            XCTAssertNil(wrongType)
            
            // Unsigned variants
            
            let testUInt: UInt = UInt.random(in: UInt.min...UInt.max)
            let encUInt = try encryptor.encode(testUInt, withKey: encKeyV1)
            let decUInt = try decryptor.decode(UInt.self, from: encUInt, withKey: encKeyV1)
            XCTAssertEqual(decUInt, testUInt)
            
            let testUInt8: UInt8 = UInt8.random(in: UInt8.min...UInt8.max)
            let encUInt8 = try encryptor.encode(testUInt8, withKey: encKeyV1)
            let decUInt8 = try decryptor.decode(UInt8.self, from: encUInt8, withKey: encKeyV1)
            XCTAssertEqual(decUInt8, testUInt8)
            
            let testUInt16: UInt16 = UInt16.random(in: UInt16.min...UInt16.max)
            let encUInt16 = try encryptor.encode(testUInt16, withKey: encKeyV1)
            let decUInt16 = try decryptor.decode(UInt16.self, from: encUInt16, withKey: encKeyV1)
            XCTAssertEqual(decUInt16, testUInt16)
            
            let testUInt32: UInt32 = UInt32.random(in: UInt32.min...UInt32.max)
            let encUInt32 = try encryptor.encode(testUInt32, withKey: encKeyV1)
            let decUInt32 = try decryptor.decode(UInt32.self, from: encUInt32, withKey: encKeyV1)
            XCTAssertEqual(decUInt32, testUInt32)
            
            let testUInt64: UInt64 = UInt64.random(in: UInt64.min...UInt64.max)
            let encUInt64 = try encryptor.encode(testUInt64, withKey: encKeyV1)
            let decUInt64 = try decryptor.decode(UInt64.self, from: encUInt64, withKey: encKeyV1)
            XCTAssertEqual(decUInt64, testUInt64)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testFloatEncryption() {
        
        do {
            // Finite
            
            let testPos: Float = 41.263451812345
            let encPos = try encryptor.encode(testPos, withKey: encKeyV1)
            let decPos = try decryptor.decode(Float.self, from: encPos, withKey: encKeyV1)
            XCTAssertEqual(decPos, testPos)
            
            let testNeg: Float = -32.34324523549
            let encNeg = try encryptor.encode(testNeg, withKey: encKeyV1)
            let decNeg = try decryptor.decode(Float.self, from: encNeg, withKey: encKeyV1)
            XCTAssertEqual(decNeg, testNeg)
            
            // Infinite
            
            let testInfinity: Float = Float.infinity
//            let encInfinityFail = try? encryptor.encode(testInfinity, withKey: encKey)
//            XCTAssertNil(encInfinityFail)
            
//            encryptor.nonConformingFloatEncodingStrategy = .convertToString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
            let encInfinity = try encryptor.encode(testInfinity, withKey: encKeyV1)
            
//            let decInfinityFail = try? decryptor.decode(Float.self, from: encInfinity, withKey: encKey)
//            XCTAssertNil(decInfinityFail)
            
//            decryptor.nonConformingFloatDecodingStrategy = .convertFromString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
            let decInfinity = try decryptor.decode(Float.self, from: encInfinity, withKey: encKeyV1)
            XCTAssertEqual(decInfinity, testInfinity)
            
            let testNegInfinity: Float = -Float.infinity
            let encNegInfinity = try encryptor.encode(testNegInfinity, withKey: encKeyV1)
            let decNegInfinity = try decryptor.decode(Float.self, from: encNegInfinity, withKey: encKeyV1)
            XCTAssertEqual(decNegInfinity, testNegInfinity)
            
            // Not a number
            
            let testNaN: Float = Float.nan
            let encNaN = try encryptor.encode(testNaN, withKey: encKeyV1)
            let decNaN = try decryptor.decode(Float.self, from: encNaN, withKey: encKeyV1)
            XCTAssert(decNaN.isNaN)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testDoubleEncryption() {
        
        do {
            // Finite
            
            let testPos: Double = 41.263451812345
            let encPos = try encryptor.encode(testPos, withKey: encKeyV1)
            let decPos = try decryptor.decode(Double.self, from: encPos, withKey: encKeyV1)
            XCTAssertEqual(decPos, testPos)
            
            let testNeg: Double = -32.34324523549
            let encNeg = try encryptor.encode(testNeg, withKey: encKeyV1)
            let decNeg = try decryptor.decode(Double.self, from: encNeg, withKey: encKeyV1)
            XCTAssertEqual(decNeg, testNeg)
            
            // Infinite
            
            let testInfinity: Double = Double.infinity
//            let encInfinityFail = try? encryptor.encode(testInfinity, withKey: encKey)
//            XCTAssertNil(encInfinityFail)
            
//            encryptor.nonConformingFloatEncodingStrategy = .convertToString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
            let encInfinity = try encryptor.encode(testInfinity, withKey: encKeyV1)
            
//            let decInfinityFail = try? decryptor.decode(Double.self, from: encInfinity, withKey: encKey)
//            XCTAssertNil(decInfinityFail)
            
//            decryptor.nonConformingFloatDecodingStrategy = .convertFromString(positiveInfinity: "inf", negativeInfinity: "-inf", nan: "NaN")
            let decInfinity = try decryptor.decode(Double.self, from: encInfinity, withKey: encKeyV1)
            XCTAssertEqual(decInfinity, testInfinity)
            
            let testNegInfinity: Double = -Double.infinity
            let encNegInfinity = try encryptor.encode(testNegInfinity, withKey: encKeyV1)
            let decNegInfinity = try decryptor.decode(Double.self, from: encNegInfinity, withKey: encKeyV1)
            XCTAssertEqual(decNegInfinity, testNegInfinity)
            
            // Not a number
            
            let testNaN: Double = Double.nan
            let encNaN = try encryptor.encode(testNaN, withKey: encKeyV1)
            let decNaN = try decryptor.decode(Double.self, from: encNaN, withKey: encKeyV1)
            XCTAssert(decNaN.isNaN)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testDateEncryption() {
        
        do {
            let testNow = Date()
            let encNow = try encryptor.encode(testNow, withKey: encKeyV1)
            let decNow = try decryptor.decode(Date.self, from: encNow, withKey: encKeyV1)
            XCTAssertEqual(decNow, testNow)
            
            let testDistantFuture = Date.distantFuture
            let encFuture = try encryptor.encode(testDistantFuture, withKey: encKeyV1)
            let decFuture = try decryptor.decode(Date.self, from: encFuture, withKey: encKeyV1)
            XCTAssertEqual(decFuture, testDistantFuture)
            
            let testDistantPast = Date.distantPast
            let encPast = try encryptor.encode(testDistantPast, withKey: encKeyV1)
            let decPast = try decryptor.decode(Date.self, from: encPast, withKey: encKeyV1)
            XCTAssertEqual(decPast, testDistantPast)
            
            // ISO-8601
            
            let isoDate = Date()
            
//            encryptor.dateEncodingStrategy = .iso8601
//            decryptor.dateDecodingStrategy = .iso8601
            let encIsoDate = try encryptor.encode(isoDate, withKey: encKeyV1)
            let decIsoDate = try decryptor.decode(Date.self, from: encIsoDate, withKey: encKeyV1)
            // We cannot guarantee exact equality here, so we compare the integer of their reference intervals.
            XCTAssertEqual(Int(decIsoDate.timeIntervalSinceReferenceDate),
                           Int(isoDate.timeIntervalSinceReferenceDate))
            
            // Since 1970
            
            let secondsDate = Date()
            
//            encryptor.dateEncodingStrategy = .secondsSince1970
//            decryptor.dateDecodingStrategy = .secondsSince1970
            let encSecondsDate = try encryptor.encode(secondsDate, withKey: encKeyV1)
            let decSecondsDate = try decryptor.decode(Date.self, from: encSecondsDate, withKey: encKeyV1)
            // We cannot guarantee exact equality here, so we compare the integer of their reference intervals.
            XCTAssertEqual(Int(decSecondsDate.timeIntervalSinceReferenceDate),
                           Int(secondsDate.timeIntervalSinceReferenceDate))
            
            let millisecondsDate = Date()
            
//            encryptor.dateEncodingStrategy = .millisecondsSince1970
//            decryptor.dateDecodingStrategy = .millisecondsSince1970
            let encMilliDate = try encryptor.encode(millisecondsDate, withKey: encKeyV1)
            let decMilliDate = try decryptor.decode(Date.self, from: encMilliDate, withKey: encKeyV1)
            // We cannot guarantee exact equality here, so we compare the integer of their reference intervals.
            XCTAssertEqual(Int(decMilliDate.timeIntervalSinceReferenceDate),
                           Int(millisecondsDate.timeIntervalSinceReferenceDate))
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testDataEncryption() {
        
        do {
            let testData = Data(repeating: 9, count: 140_000) // 140KB
            
//            encryptor.dataEncodingStratety = .raw
//            decryptor.dataDecodingStrategy = .raw
            let encRawData = try encryptor.encode(testData, withKey: encKeyV1)
            let decRawData = try decryptor.decode(Data.self, from: encRawData, withKey: encKeyV1)
            XCTAssertEqual(decRawData, testData)
            
//            encryptor.dataEncodingStratety = .base64
//            decryptor.dataDecodingStrategy = .base64
//            let encStringData = try encryptor.encode(testData, withKey: encKey)
//            let decStringData = try decryptor.decode(Data.self, from: encStringData, withKey: encKey)
//            XCTAssertEqual(decStringData, testData)
//
//            encryptor.dataEncodingStratety = .deferredToData
//            decryptor.dataDecodingStrategy = .deferredToData
//            let encDeferredData = try encryptor.encode(testData, withKey: encKey)
//            let decDeferredData = try decryptor.decode(Data.self, from: encDeferredData, withKey: encKey)
//            XCTAssertEqual(decDeferredData, testData)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testKeyedEncryption() {
        let testCodable = EncodableThing()
        
        do {
            let encCodable = try encryptor.encode(testCodable, withKey: encKeyV1)
            let decCodable = try decryptor.decode(EncodableThing.self, from: encCodable, withKey: encKeyV1)
            XCTAssertEqual(decCodable, testCodable)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testUnkeyedEncryption() {
        let testCodables = [EncodableThing(),
                            EncodableThing(thingOne: "Some", thingTwo: "One", andAnotherThing: 2),
                            EncodableThing()]
        
        do {
            let encCodables = try encryptor.encode(testCodables, withKey: encKeyV1)
            let decCodables = try decryptor.decode([EncodableThing].self, from: encCodables, withKey: encKeyV1)
            XCTAssertEqual(decCodables, testCodables)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testNilEncryption() {
        do {
            _ = try encryptor.encode(NullValue(), withPassword: password)
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testPropertyListEncryption() {
        let testData = ["root": "branch",
                        "more?": "leaf",
                        "integeryay": "3"]
        let plistEncoder = PropertyListEncoder()
        plistEncoder.outputFormat = .binary
        do {
            let plistData = try plistEncoder.encode(testData)
            
            let encPlist = try encryptor.encode(plistData, withKey: encKeyV1)
            let decPlist = try decryptor.decode(Data.self, from: encPlist, withKey: encKeyV1)
            XCTAssertEqual(decPlist, plistData)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    
    
    // MARK: - Encrypted Item
    
    func testEncryptedDataParse() {
        do {
            let testText = "Lorem ipsum dolor sit amet"
            
            let encryptedItem = try encryptor.encode(testText, withPassword: password)
            let testDecryptedString = try decryptor.decode(String.self, from: encryptedItem, withPassword: password)
            XCTAssertEqual(testDecryptedString, testText)
            
            let encryptedData = encryptedItem.rawData
            
            let newItem = try EncryptedItem(data: encryptedData)
            XCTAssertEqual(newItem, encryptedItem)
            XCTAssertEqual(newItem.rawData, encryptedData)
            
            do {
                let decryptedString = try decryptor.decode(String.self, from: newItem, withPassword: password)
                XCTAssertEqual(decryptedString, testText)
                
            } catch {
                XCTFail("Failed to decrypt: \(error)")
            }
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testEncryptedItemCopy() {
        do {
            let testText = "Lorem ipsum dolor sit amet"
            
            let encryptedItem = try encryptor.encode(testText, withPassword: password)
            let itemCopy = EncryptedItem(encryptedItem)
            
            XCTAssertEqual(itemCopy, encryptedItem, "The items are not identical!")
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testEncryptedItemSet() {
        do {
            let testText = "Lorem ipsum dolor sit amet"
            let testInt = 14_003
            
            let encryptedText = try encryptor.encode(testText, withPassword: password)
            let encryptedInt = try encryptor.encode(testInt, withPassword: password)
            let itemCopy = EncryptedItem(encryptedInt)
            
            var itemSet = Set<EncryptedItem>()
            itemSet.insert(encryptedText)
            itemSet.insert(encryptedInt)
            XCTAssertEqual(itemSet.count, 2, "There are not 2 items in the set. Found \(itemSet.count)")
            
            itemSet.insert(itemCopy)
            XCTAssertEqual(itemSet.count, 2, "The item seems to have been added to the set. Found \(itemSet.count) in the set.")
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testEncryptedItemFromBogusData() {
        let randomData = Data(repeating: UInt8.random(in: 0...9), count: 16)
        
        do {
            let item = try EncryptedItem(data: randomData)
            XCTFail("Random data shouldn't create an EncryptedItem: \(item.rawData)")
            
        } catch {
            XCTAssert(error is EncryptionSerialization.DecryptionError, "Got a different error: \(error)")
        }
        
    }
    
    func testEncryptedDataWithoutPassword() {
        let randomData = Data(repeating: UInt8.random(in: 0...9), count: 16)
        
        do {
            _ = try encryptor.encode(randomData, withPassword: "")
            XCTFail("Encryptor should throw at empty password string.")
        } catch let error as EncryptionSerialization.EncryptionError {
            XCTAssertEqual(error, .noPassword)
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testDecryptedDataWithoutPassword() {
        let testText = "Lorem ipsum dolor sit amet"
        
        do {
            let encryptedItem = try encryptor.encode(testText, withPassword: password)
            _ = try decryptor.decode(String.self, from: encryptedItem, withPassword: "")
            XCTFail("Decryptor should throw at empty password string.")
            
        } catch let error as EncryptionSerialization.DecryptionError {
            XCTAssertEqual(error, .noPassword)
            
        } catch {
            XCTFail("\(error)")
        }
    }
    
//    func testDecryptedDataFromMismatchingSchemes() {
//        let randomData = Data(repeating: UInt8.random(in: 0...9), count: 16)
//
//        do {
//            let encryptedItem = try encryptor.encode(randomData, withKey: encKey)
//
//            let oddScheme = EncryptionSerialization.Scheme(format: .unused)
//            let oddSeed = EncryptionSerialization.randomBytes(count: oddScheme.seedSize)
//            let oddIV = EncryptionSerialization.randomBytes(count: oddScheme.initializationVectorSize)
//            let oddKey = try EncryptionKey(untreatedPassword: "doesn't matter", seed: oddSeed, iv: oddIV, scheme: oddScheme)
//
//            let decoded = try decryptor.decode(Data.self, from: encryptedItem, withKey: oddKey)
//            XCTFail("Odd scheme shouldn't decode anything: \(decoded)")
//
//        } catch let error as EncryptionSerialization.DecryptionError {
//            XCTAssertEqual(error, .incorrectVersion)
//
//        } catch {
//            XCTFail("\(error)")
//        }
//    }
    
    
    // MARK: - Encryption Keys
    
    func testEncryptionKeyFromPassword() {
        let userId = "thisIsMyUserID1234"
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let randomIV = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        do {
            let newTestKey = try EncryptionKey(untreatedPassword: password,
                                                additionalKeywords: [userId],
                                                seed: randomSeed,
                                                iv: randomIV,
                                                scheme: scheme)
            
            // Store the salt for later...
            let storedSalt = newTestKey.salt
            let storedIV = newTestKey.initializationVector
            
            // ... and now use it.
            let derivedKey = try EncryptionKey(untreatedPassword: password,
                                                treatedSalt: storedSalt,
                                                iv: storedIV,
                                                scheme: scheme)
            XCTAssertEqual(derivedKey, newTestKey)
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testIdenticalKeys() {
        let userID = "thisIsMyUserIdDoYouLikeIt123"
        let email = "myself@example.com"
        
        let scheme = EncryptionSerialization.Scheme.default
        let seed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let iv = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        
        let firstKey: EncryptionKey
        let secondKey: EncryptionKey
        do {
            firstKey = try EncryptionKey(untreatedPassword: password,
                                         additionalKeywords: [userID, email],
                                         seed: seed,
                                         iv: iv,
                                         scheme: scheme)
            secondKey = try EncryptionKey(untreatedPassword: password,
                                          additionalKeywords: [userID, email],
                                          seed: seed,
                                          iv: iv,
                                          scheme: scheme)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        XCTAssertEqual(firstKey, secondKey)
    }
    
    func testEncryptionKeyKeywordOrder() {
        // Two keys should be unequal whose additionalKeywords are in a different order.
        let userId = "thisIsMyUserIdDoYouLikeIt123"
        let email = "myself@example.com"
        
        let scheme = EncryptionSerialization.Scheme.default
        let seed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let iv = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        
        let firstKey: EncryptionKey
        let secondKey: EncryptionKey
        do {
            firstKey = try EncryptionKey(untreatedPassword: password,
                                         additionalKeywords: [userId, email],
                                         seed: seed,
                                         iv: iv,
                                         scheme: scheme)
            secondKey = try EncryptionKey(untreatedPassword: password,
                                          additionalKeywords: [email, userId],
                                          seed: seed,
                                          iv: iv,
                                          scheme: scheme)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        XCTAssertNotEqual(firstKey, secondKey)
    }
    
    func testEncryptionKeyMismatchKeywords() {
        let userId = "thisIsMyUserID1234@example.com"
        
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let randomIV = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        let goodKey: EncryptionKey
        do {
            goodKey = try EncryptionKey(untreatedPassword: password,
                                           additionalKeywords: [userId],
                                           seed: randomSeed,
                                           iv: randomIV,
                                           scheme: scheme)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        let someData = Data(repeating: UInt8.random(in: UInt8.min...UInt8.max), count: 24)
        let encData: EncryptedItem
        let badKey: EncryptionKey
        do {
            encData = try encryptor.encode(someData, withKey: goodKey)
            badKey = try EncryptionKey(untreatedPassword: password,
                                           additionalKeywords: ["someOtherGuy@example.com"],
                                           seed: randomSeed,
                                           iv: randomIV,
                                           scheme: scheme)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        do {
            _ = try decryptor.decode(Data.self, from: encData, withKey: badKey)
            XCTFail("Decryptor shouldn't be able to decrypt without proper user info.")
            
        } catch is DecodingError {
            // great!
        } catch {
            XCTFail("\(error)")
        }
        
        do {
            let goodData = try decryptor.decode(Data.self, from: encData, withKey: goodKey)
            XCTAssertEqual(goodData, someData)
            
        } catch {
            XCTFail("\(error)")
        }
        
    }
    
    func testSetOfKeys() {
        let scheme = EncryptionSerialization.Scheme.default
        
        let key1 = EncryptionKey(randomKeyFromPassword: password, scheme: scheme)
        let key2 = EncryptionKey(randomKeyFromPassword: password, scheme: scheme)
        let key3 = EncryptionKey(randomKeyFromPassword: password, scheme: scheme)
        
        var keySet = Set<EncryptionKey>()
        keySet.insert(key1)
        keySet.insert(key2)
        keySet.insert(key3)
        keySet.insert(key1)
        XCTAssertEqual(keySet.count, 3)
        
    }
    
    
    
    // MARK: - Keychain Handle
    
    func testEncryptionKeyStorage() {
        
        let tag = "com.LeadDevCreations.keys.testKey"
        let storage = KeychainHandle()
        
        do {
            try storage.deleteKey(withTag: tag)
        } catch {
            XCTFail("\(error)")
        }
        
        do {
            let notThereYet: EncryptionKey? = try storage.key(withTag: tag)
            XCTAssertNil(notThereYet, "The key was found in storage!")
            let keyExists = storage.keyExists(ofType: EncryptionKey.self, withTag: tag)
            XCTAssertFalse(keyExists, "A key was found in storage!")
        } catch {
            XCTFail("Failed to grab nonexistent key: \(error)")
        }
        
        do {
            try storage.setKey(encKeyV1, forTag: tag)
            let storedKey: EncryptionKey? = try storage.key(withTag: tag)
            XCTAssertNotNil(storedKey, "The item was not retrieved from storage.")
        } catch {
            XCTFail("Failed to store key: \(error)")
        }
        
        do {
            let goneKey: EncryptionKey? = try storage.deleteKey(withTag: tag)
            XCTAssertNotNil(goneKey, "The item was not returned after deletion.")
        } catch {
            XCTFail("Failed to delete key: \(error)")
        }
        
        do {
            let notThereAnymore: EncryptionKey? = try storage.key(withTag: tag)
            XCTAssertNil(notThereAnymore)
            
        } catch {
            XCTFail("Failed to grab now nonexistent key: \(error)")
        }
        
    }
    
    func testKeychainAccessSubscript() {
        
        let tag = "com.LeadDevCreations.keys.testKey"
        let storage = KeychainHandle()
        
        do {
            try storage.deleteKey(withTag: tag)
        } catch {
            XCTFail("\(error)")
        }
        
        let notThereYet = storage[tag]
        XCTAssertNil(notThereYet, "The key was found in storage!")
        
        storage[tag] = encKeyV1
        
        let storedKey = storage[tag]
        XCTAssertNotNil(storedKey, "The item was not retrieved from storage.")
        
        storage[tag] = nil
        
        do {
            let notThereAnymore: EncryptionKey? = try storage.key(withTag: tag)
            XCTAssertNil(notThereAnymore)
            
        } catch {
            XCTFail("Failed to grab now nonexistent key: \(error)")
        }
        
    }
    
    
    
    // MARK - Performance
    
    func testEncryptionPerformance() {
        let testString = "Lorem ipsum dolor sit amet"
        
        measure {
            do {
                _ = try encryptor.encode(testString, withPassword: password)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testDecryptionPerformance() {
        let testString = "Lorem ipsum dolor sit amet"
        let encryptedItem: EncryptedItem
        do {
            encryptedItem = try encryptor.encode(testString, withPassword: password)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try decryptor.decode(String.self, from: encryptedItem, withPassword: password)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testEncryptionPerformanceWithKey() {
        let testString = "Lorem ipsum dolor sit amet"
        
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let randomIV = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        let encKey: EncryptionKey
        do {
            encKey = try EncryptionKey(untreatedPassword: password, seed: randomSeed, iv: randomIV, scheme: scheme)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try encryptor.encode(testString, withKey: encKey)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testDecryptionPerformanceWithKey() {
        let testString = "Lorem ipsum dolor sit amet"
        
        let scheme = EncryptionSerialization.Scheme.default
        let randomSeed = EncryptionSerialization.randomBytes(count: scheme.seedSize)
        let randomIV = EncryptionSerialization.randomBytes(count: scheme.initializationVectorSize)
        let encKey: EncryptionKey
        let encryptedString: EncryptedItem
        do {
            encKey = try EncryptionKey(untreatedPassword: password, seed: randomSeed, iv: randomIV, scheme: scheme)
            encryptedString = try encryptor.encode(testString, withKey: encKey)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try decryptor.decode(String.self, from: encryptedString, withKey: encKey)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testBase64EncryptionPerformance() {
        
        let testData = Data(repeating: 9, count: 140_000) // 140KB
        let base64Data = testData.base64EncodedString()
        
//        encryptor.dataEncodingStratety = .base64
        measure {
            do {
                _ = try encryptor.encode(base64Data, withKey: encKeyV1)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testBase64DecryptionPerformance() {
        
        let testData = Data(repeating: 9, count: 140_000) // 140KB
        let base64Data = testData.base64EncodedString()
        
//        encryptor.dataEncodingStratety = .base64
//        decryptor.dataDecodingStrategy = .base64
        let encData: EncryptedItem
        do {
            encData = try encryptor.encode(base64Data, withKey: encKeyV1)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try decryptor.decode(String.self, from: encData, withKey: encKeyV1)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testRawEncryptionPerformance() {
        
        let testData = Data(repeating: 9, count: 140_000) // 140KB
        
//        encryptor.dataEncodingStratety = .raw
        measure {
            do {
                _ = try encryptor.encode(testData, withKey: encKeyV1)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
    func testRawDecryptionPerformance() {
        
        let testData = Data(repeating: 9, count: 140_000) // 140KB
        
//        encryptor.dataEncodingStratety = .raw
//        decryptor.dataDecodingStrategy = .raw
        
        let encData: EncryptedItem
        do {
            encData = try encryptor.encode(testData, withKey: encKeyV1)
        } catch {
            XCTFail("\(error)")
            return
        }
        
        measure {
            do {
                _ = try decryptor.decode(Data.self, from: encData, withKey: encKeyV1)
            } catch {
                XCTFail("\(error)")
            }
        }
        
    }
    
}



struct NullValue: Codable, Equatable {
    
    static func == (lhs: NullValue, rhs: NullValue) -> Bool {
        return true
    }
    
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

struct EncodableThing: Codable, Equatable {
    
    enum CodingKeys: CodingKey {
        case thingOne
        case thingTwo
        case andAnotherThing
    }
    
    let thingOne: String
    let thingTwo: String
    let andAnotherThing: Int
    
    static func == (lhs: EncodableThing, rhs: EncodableThing) -> Bool {
        return (lhs.thingOne == rhs.thingOne &&
            lhs.thingTwo == rhs.thingTwo &&
            lhs.andAnotherThing == rhs.andAnotherThing)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(thingOne, forKey: .thingOne)
        try container.encode(thingTwo, forKey: .thingTwo)
        try container.encode(andAnotherThing, forKey: .andAnotherThing)
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        thingOne = try container.decode(String.self, forKey: .thingOne)
        thingTwo = try container.decode(String.self, forKey: .thingTwo)
        andAnotherThing = try container.decode(Int.self, forKey: .andAnotherThing)
    }
    
    init(thingOne: String = "First!", thingTwo: String = "NexT!", andAnotherThing: Int = 1) {
        self.thingOne = thingOne
        self.thingTwo = thingTwo
        self.andAnotherThing = andAnotherThing
    }
    
}
