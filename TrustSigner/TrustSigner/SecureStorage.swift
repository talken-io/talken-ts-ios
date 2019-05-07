//
//  SecureStorage.swift
//  Talken
//
//  Created by master Jun on 18/02/2019.
//  Copyright © 2019 master Jun. All rights reserved.
//

import Foundation

class SecureStorage {
    static var publicKey : SecKey?
    static var privateKey : SecKey?
    
    static let SECURE_USER_DEFAULTS = "secure_trustsigner_defaults";
    static let tagPrivate = "io.talken.trustsigner.tagPrivate"
    static let tagPublic = "io.talken.trustsigner.tagPublic"
    
    //set/get 루틴
    //set : plainText(String) -> Encrypt with publicKey ([UInt8]) -> transffer [UInt8] to Data (Data) -> Save UserDefault
    //get : cipherData(Data) -> transfer Data to [UInt8]([UInt8]) -> Decrypt with privateKey([UInt8]) -> transfer [UInt8] to String
    static func setSecureUserDefault(key : String, value : String) -> Bool {
        let encryptValue = encrypt(plainText :value)
        if encryptValue != nil {
            UserDefaults(suiteName: SECURE_USER_DEFAULTS)?.set(encryptValue, forKey: key)
            return true
        }
        return false
    }
    
    static func getSecureUserDefault(key : String) -> String? {
        guard let savedValue : Data = UserDefaults(suiteName: SECURE_USER_DEFAULTS)?.data(forKey: key) else {
            return nil
        }
        let result = decrypt(cipherData :savedValue)
        return result
    }
    
    static func clearSecureStorage() {
        let dictionary = UserDefaults(suiteName: SECURE_USER_DEFAULTS)?.dictionaryRepresentation()
        dictionary?.keys.forEach { key in
            UserDefaults(suiteName: SECURE_USER_DEFAULTS)?.removeObject(forKey: key)
        }
        deleteAllKeysInKeyChain()
    }
    
    private static func encrypt(plainText : String) -> Data? {
        if !getExistKeypair() {
            generateKeypair()
        }
        
        //Encrypt with publicKey
        let blockSize = SecKeyGetBlockSize(publicKey!)
        var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
        var messageEncryptedSize = blockSize
        
        var status : OSStatus!
        status = SecKeyEncrypt(publicKey!, SecPadding.PKCS1, plainText, plainText.count, &messageEncrypted, &messageEncryptedSize)
        
        if status != noErr {
            return nil
        } else {
            //[UInt8] to Data
            return Data(bytes: &messageEncrypted, count: messageEncryptedSize)
        }
    }
    
    private static func decrypt(cipherData : Data) -> String?{
        if !getExistKeypair() {
            return nil
        }
        
        let messageEncrypted = [UInt8](cipherData)
        
        let blockSize = SecKeyGetBlockSize(privateKey!)
        var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
        var messageDecryptedSize = blockSize
        
        var status : OSStatus!
        status = SecKeyDecrypt(privateKey!, SecPadding.PKCS1, messageEncrypted, messageEncrypted.count, &messageDecrypted, &messageDecryptedSize)
        
        if status != noErr {
            return nil
        } else {
            let data = Data(bytes: UnsafePointer<UInt8>(messageDecrypted), count: messageDecryptedSize)
            let result = String(data: data, encoding: .utf8)
            return result
        }
    }
    
    private static func getExistKeypair() -> Bool {
        privateKey = getKeysFromKeychain(tag: tagPrivate)
        publicKey = getKeysFromKeychain(tag: tagPublic)
        
        return ((privateKey != nil) && (publicKey != nil))
    }
    
    private static func getKeysFromKeychain(tag : String) -> SecKey? {
        let query : [String : AnyObject] = [
            String(kSecClass) : kSecClassKey,
            String(kSecAttrKeyType) : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tag as AnyObject,
            String(kSecReturnRef) : true as AnyObject
        ]
        
        var result : AnyObject?
        
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            return result as! SecKey?
        }
        return nil
    }
    
    private static func generateKeypair() {
        let privateKeyAttr : [NSString : AnyObject] = [
            kSecAttrIsPermanent : true as AnyObject,
            kSecAttrApplicationTag : tagPrivate as AnyObject
        ]
        
        let publicKeyAttr : [NSString : AnyObject] = [
            kSecAttrIsPermanent : true as AnyObject,
            kSecAttrApplicationTag : tagPublic as AnyObject
        ]
        
        let paramters : [String : AnyObject] = [
            kSecAttrKeyType as String : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String : 2048 as AnyObject,
            kSecPrivateKeyAttrs as String : privateKeyAttr as AnyObject,
            kSecPublicKeyAttrs as String : publicKeyAttr as AnyObject
        ]
        
        let status = SecKeyGeneratePair(paramters as CFDictionary, &publicKey, &privateKey)
        print("generateKeypair status[\(status)]")
    }
    
    private static func deleteAllKeysInKeyChain() {
        let query : [String: AnyObject] = [String(kSecClass) : kSecClassKey]
        let status = SecItemDelete(query as CFDictionary)
        
        switch status {
        case errSecItemNotFound:
            print("No key in keychain")
        case noErr:
            print("All Keys Deleted!")
        default:
            print("SecItemDelete error! \(status.description)")
        }
    }
}
