//
//  KeySizes.swift
//  ItemEncrypt
//
//  Created on 5/15/19.
//

import Foundation
import CommonCrypto

struct KeySize {
    
    let rawValue: UInt
    
    static let aes128       = KeySize(rawValue: UInt(kCCKeySizeAES128))
    static let aes192       = KeySize(rawValue: UInt(kCCKeySizeAES192))
    static let aes256       = KeySize(rawValue: UInt(kCCKeySizeAES256))
    static let des          = KeySize(rawValue: UInt(kCCKeySizeDES))
    static let tripleDES    = KeySize(rawValue: UInt(kCCKeySize3DES))
    static let castMin      = KeySize(rawValue: UInt(kCCKeySizeMinCAST))
    static let castMax      = KeySize(rawValue: UInt(kCCKeySizeMaxCAST))
    static let rc2Min       = KeySize(rawValue: UInt(kCCKeySizeMinRC2))
    static let rc2Max       = KeySize(rawValue: UInt(kCCKeySizeMaxRC2))
    static let blowfishMin  = KeySize(rawValue: UInt(kCCKeySizeMinBlowfish))
    static let blowfishMax  = KeySize(rawValue: UInt(kCCKeySizeMaxBlowfish))
    
}
