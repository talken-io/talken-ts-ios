//
//  TrustSigner.swift
//  TrustSigner
//
//  Created by Seo Minyeol on 24/04/2019.
//  Copyright © 2019 Minyeol Seo. All rights reserved.
//

import Foundation
import LibTrustSigner

open class TrustSigner {
    let VERSION: String = "0.9.1"
    let PREFERENCE_WB: String = "trustsigner.wbd"
    
    var mAppID:  String? = nil
    var mWbPath: String? = nil
    var mWbData: Array<UInt8>? = nil
    
    var pAppID:  UnsafeMutablePointer<Int8>? = nil
    var pWbPath: UnsafeMutablePointer<Int8>? = nil
    var pWbData: UnsafeMutablePointer<UInt8>? = nil
    
    public init (appID: String) {
        mAppID = String(appID)
        mWbPath = getApplicationDirectory().path
        if (mAppID == nil || mWbPath == nil) {
            print("Error! App id or path is NULL!")
            return
        }
        
        if (pAppID != nil) {
            pAppID!.deinitialize(count: mAppID!.count + 1)
            pAppID?.deallocate()
        }
        pAppID = UnsafeMutablePointer<Int8>.allocate(capacity: mAppID!.count + 1)
        pAppID!.initialize(repeating: 0, count: mAppID!.count + 1)
        pAppID!.initialize(from: mAppID!, count: mAppID!.count)
        
        if (pWbPath != nil) {
            pWbPath!.deinitialize(count: mWbPath!.count + 1)
            pWbPath?.deallocate()
        }
        pWbPath = UnsafeMutablePointer<Int8>.allocate(capacity: mWbPath!.count + 1)
        pWbPath!.initialize(repeating: 0, count: mWbPath!.count + 1)
        pWbPath!.initialize(from: mWbPath!, count: mWbPath!.count)

        let strWbData: String! = getStringSharedPreference(key: PREFERENCE_WB);
        if (strWbData == nil) {
            print("@@@@@@@ TrustSigner WB Table Create @@@@@@@")
            pWbData = TrustSigner_getWBInitializeData(pAppID, pWbPath);
            if (pWbData == nil) {
                print("Error! WB initialize failed.")
                if (pAppID != nil) {
                    pAppID!.deinitialize(count: mAppID!.count + 1)
                    pAppID?.deallocate()
                }
                if (pWbPath != nil) {
                    pWbPath!.deinitialize(count: mWbPath!.count + 1)
                    pWbPath?.deallocate()
                }
                if (pWbData != nil) {
                    pWbData!.deinitialize(count: mWbData!.count + 1)
                    pWbData?.deallocate()
                }
                return
            }

            let retLength: Int = getDataLength(array: Array(UnsafeBufferPointer(start: pWbData, count: 4)))
            mWbData = Array(UnsafeBufferPointer(start: pWbData, count: retLength + 4)) // 68
            if (putStringSharedPreference(key: PREFERENCE_WB, value: byteArrayToHexString(byteArray: mWbData!)) == false) {
                print("Error! WB secure save failed.")
                if (pAppID != nil) {
                    pAppID!.deinitialize(count: mAppID!.count + 1)
                    pAppID?.deallocate()
                }
                if (pWbPath != nil) {
                    pWbPath!.deinitialize(count: mWbPath!.count + 1)
                    pWbPath?.deallocate()
                }
                if (pWbData != nil) {
                    pWbData!.deinitialize(count: mWbData!.count + 1)
                    pWbData?.deallocate()
                }
                mWbData = nil
                return
            }
        } else {
            print("@@@@@@@ TrustSigner WB Table Load @@@@@@@")
            mWbData = hexStringToByteArray(hexString: strWbData)
            if (pWbData != nil) {
                if (pAppID != nil) {
                    pAppID!.deinitialize(count: mAppID!.count + 1)
                    pAppID?.deallocate()
                }
                if (pWbPath != nil) {
                    pWbPath!.deinitialize(count: mWbPath!.count + 1)
                    pWbPath?.deallocate()
                }
                if (pWbData != nil) {
                    pWbData!.deinitialize(count: mWbData!.count + 1)
                    pWbData?.deallocate()
                }
            }
            pWbData = UnsafeMutablePointer<UInt8>.allocate(capacity: mWbData!.count + 1)
            pWbData!.initialize(repeating: 0, count: mWbData!.count + 1)
            pWbData!.initialize(from: mWbData!, count: mWbData!.count)
        }
    }
    
    deinit {
        if (pAppID != nil) {
            pAppID!.deinitialize(count: mAppID!.count + 1)
            pAppID?.deallocate()
        }
        if (pWbPath != nil) {
            pWbPath!.deinitialize(count: mWbPath!.count + 1)
            pWbPath?.deallocate()
        }
        if (pWbData != nil) {
            pWbData!.deinitialize(count: mWbData!.count + 1)
            pWbData?.deallocate()
        }
    }
    
    private func getDataLength (array: [UInt8]) -> Int {
        var value: Int = 0
        let data = NSData(bytes: array, length: 4)
        data.getBytes(&value, length: 4)
        return value
    }
    
    private func getApplicationDirectory() -> URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        return paths[0]
    }
    
    private func putStringSharedPreference (key: String, value: String) -> Bool {
        return SecureStorage.setSecureUserDefault(key: key, value: value)
    }
    
    private func getStringSharedPreference (key: String) -> String? {
        return SecureStorage.getSecureUserDefault(key: key)
    }
    
    public func getVersion () -> String {
        return VERSION
    }
    
    public func initialize (appID: String) -> Bool {
        mAppID = String(appID)
        mWbPath = getApplicationDirectory().path
        if (mAppID == nil || mWbPath == nil) {
            print("Error! App id or path is NULL!")
            return false
        }
        
        if (pAppID != nil) {
            pAppID!.deinitialize(count: mAppID!.count + 1)
            pAppID?.deallocate()
        }
        pAppID = UnsafeMutablePointer<Int8>.allocate(capacity: mAppID!.count + 1)
        pAppID!.initialize(repeating: 0, count: mAppID!.count + 1)
        pAppID!.initialize(from: mAppID!, count: mAppID!.count)
        
        if (pWbPath != nil) {
            pWbPath!.deinitialize(count: mWbPath!.count + 1)
            pWbPath?.deallocate()
        }
        pWbPath = UnsafeMutablePointer<Int8>.allocate(capacity: mWbPath!.count + 1)
        pWbPath!.initialize(repeating: 0, count: mWbPath!.count + 1)
        pWbPath!.initialize(from: mWbPath!, count: mWbPath!.count)
        
        pWbData = TrustSigner_getWBInitializeData(pAppID, pWbPath);
        if (pWbData == nil) {
            print("Error! WB initialize failed.")
            if (pAppID != nil) {
                pAppID!.deinitialize(count: mAppID!.count + 1)
                pAppID?.deallocate()
            }
            if (pWbPath != nil) {
                pWbPath!.deinitialize(count: mWbPath!.count + 1)
                pWbPath?.deallocate()
            }
            if (pWbData != nil) {
                pWbData!.deinitialize(count: mWbData!.count + 1)
                pWbData?.deallocate()
            }
            return false
        }
        
        let retLength: Int = getDataLength(array: Array(UnsafeBufferPointer(start: pWbData, count: 4)))
        mWbData = Array(UnsafeBufferPointer(start: pWbData, count: retLength + 4)) // 68
        if (putStringSharedPreference(key: PREFERENCE_WB, value: byteArrayToHexString(byteArray: mWbData!)) == false) {
            print("Error! WB secure save failed.")
            if (pWbData != nil) {
                if (pAppID != nil) {
                    pAppID!.deinitialize(count: mAppID!.count + 1)
                    pAppID?.deallocate()
                }
                if (pWbPath != nil) {
                    pWbPath!.deinitialize(count: mWbPath!.count + 1)
                    pWbPath?.deallocate()
                }
                if (pWbData != nil) {
                    pWbData!.deinitialize(count: mWbData!.count + 1)
                    pWbData?.deallocate()
                }
                mWbData = nil
            }
            return false
        }
        return true
    }
    
    public func getPublicKey (coinSymbol: String, hdDepth: Int, hdChange: Int, hdIndex: Int) -> String? {
        if (mAppID == nil) {
            print("[TrustSigner] : App ID is empty!")
            return nil
        } else if (mWbData == nil) {
            print("[TrustSigner] : WB data is empty!")
            return nil
        } else if (hdDepth < 3 || hdDepth > 5) {
            print("[TrustSigner] : HD depth value invaild! (3 ~ 5)")
            return nil
        } else if (coinSymbol == "XLM" && hdDepth != 3) {
            print("[TrustSigner] : XLM HD depth value invaild! (3)")
            return nil
        } else if (hdChange < 0 || hdChange > 1) {
            print("[TrustSigner] : HD change value invaild! (0 ~ 1)")
            return nil
        } else if (hdIndex < 0) {
            print("[TrustSigner] : HD index value invaild!")
            return nil
        }
        
        let coinSym = UnsafeMutablePointer<Int8>.allocate(capacity: coinSymbol.count)
        coinSym.initialize(repeating: 0, count: coinSymbol.count + 1)
        coinSym.initialize(from: coinSymbol, count: coinSymbol.count)
        
        let pubKey: UnsafeMutablePointer<Int8>? = TrustSigner_getWBPublicKey (pAppID, pWbPath, pWbData, coinSym, Int32(hdDepth), Int32(hdChange), Int32(hdIndex))
        coinSym.deallocate()
        if (pubKey == nil) {
            print("Error! Get public key failed.")
            return nil
        }
        
        return String(cString: pubKey!)
    }
    
    public func getAccountPublicKey (coinSymbol: String) -> String? {
        if (mAppID == nil) {
            print("[TrustSigner] : App ID is empty!")
            return nil
        } else if (mWbData == nil) {
            print("[TrustSigner] : WB data is empty!")
            return nil
        }
        
        let coinSym = UnsafeMutablePointer<Int8>.allocate(capacity: coinSymbol.count + 1)
        coinSym.initialize(repeating: 0, count: coinSymbol.count + 1)
        coinSym.initialize(from: coinSymbol, count: coinSymbol.count)
        
        let pubKey: UnsafeMutablePointer<Int8>? = TrustSigner_getWBPublicKey (pAppID, pWbPath, pWbData, coinSym, 3, 0, 0)
        coinSym.deinitialize(count: coinSymbol.count + 1)
        coinSym.deallocate()
        if (pubKey == nil) {
            print("Error! Get public key failed.")
            return nil
        }
        
        return String(cString: pubKey!)
    }
    
    public func getSignatureData (coinSymbol: String, hdDepth: Int, hdChange: Int, hdIndex: Int, hashMessage: String) -> String? {
        if (mAppID == nil) {
            print("[TrustSigner] : App ID is empty!")
            return nil
        } else if (mWbData == nil) {
            print("[TrustSigner] : WB data is empty!")
            return nil
        } else if (hdDepth < 3 || hdDepth > 5) {
            print("[TrustSigner] : HD depth value invaild! (3 ~ 5)")
            return nil
        } else if (coinSymbol == "XLM" && hdDepth != 3) {
            print("[TrustSigner] : XLM HD depth value invaild! (3)")
            return nil
        } else if (hdChange < 0 || hdChange > 1) {
            print("[TrustSigner] : HD change value invaild! (0 ~ 1)")
            return nil
        } else if (hdIndex < 0) {
            print("[TrustSigner] : HD index value invaild!")
            return nil
        }
        
        let coinSym = UnsafeMutablePointer<Int8>.allocate(capacity: coinSymbol.count + 1)
        coinSym.initialize(repeating: 0, count: coinSymbol.count + 1)
        coinSym.initialize(from: coinSymbol, count: coinSymbol.count)
        let hashMsg = UnsafeMutablePointer<UInt8>.allocate(capacity: hashMessage.count/2 + 1)
        hashMsg.initialize(repeating: 0, count: hashMessage.count/2 + 1)
        hashMsg.initialize(from: hexStringToByteArray(hexString: hashMessage)!, count: hashMessage.count/2)
        
        let sign: UnsafeMutablePointer<UInt8>? = TrustSigner_getWBSignatureData (pAppID, pWbPath, pWbData, coinSym, Int32(hdDepth), Int32(hdChange), Int32(hdIndex), hashMsg, Int32(hashMessage.count/2))
        coinSym.deinitialize(count: coinSymbol.count + 1)
        coinSym.deallocate()
        hashMsg.deinitialize(count: hashMessage.count/2 + 1)
        hashMsg.deallocate()
        if (sign == nil) {
            print("Error! Get signature failed.")
            return nil
        }
    
        let retLength: Int = getDataLength(array: Array(UnsafeBufferPointer(start: sign, count: 4)))
        let signature: Array<UInt8> = Array(UnsafeBufferPointer(start: sign, count: retLength + 4))
        
        return String(byteArrayToHexString(byteArray: signature).suffix(retLength * 2))
    }
    
    public func getRecoveryData (userKey: String, serverKey: String) -> String? {
        if (mAppID == nil) {
            print("[TrustSigner] : App ID is empty!")
            return nil
        } else if (mWbData == nil) {
            print("[TrustSigner] : WB data is empty!")
            return nil
        }
        
        let usrKey = UnsafeMutablePointer<Int8>.allocate(capacity: userKey.count + 1)
        usrKey.initialize(repeating: 0, count: userKey.count + 1)
        usrKey.initialize(from: userKey, count: userKey.count)
        let srvKey = UnsafeMutablePointer<Int8>.allocate(capacity: serverKey.count + 1)
        srvKey.initialize(repeating: 0, count: serverKey.count + 1)
        srvKey.initialize(from: serverKey, count: serverKey.count)
        
        let recoveryData: UnsafeMutablePointer<Int8>? = TrustSigner_getWBRecoveryData (pAppID, pWbPath, usrKey, srvKey)
        usrKey.deinitialize(count: userKey.count + 1)
        usrKey.deallocate()
        srvKey.deinitialize(count: serverKey.count + 1)
        srvKey.deallocate()
        if (recoveryData == nil) {
            print("Error! Get recovery data failed.")
            return nil
        }
    
        return String(cString: recoveryData!)
    }
    
    public func setRecoveryData (userKey: String, recoveryData: String) -> Bool {
        if (mAppID == nil) {
            print("[TrustSigner] : App ID is empty!")
            return false
        }
        
        let usrKey = UnsafeMutablePointer<Int8>.allocate(capacity: userKey.count + 1)
        usrKey.initialize(repeating: 0, count: userKey.count + 1)
        usrKey.initialize(from: userKey, count: userKey.count)
        let recoveryDat = UnsafeMutablePointer<Int8>.allocate(capacity: recoveryData.count + 1)
        recoveryDat.initialize(repeating: 0, count: recoveryData.count + 1)
        recoveryDat.initialize(from: recoveryData, count: recoveryData.count)
        
        pWbData = TrustSigner_setWBRecoveryData (pAppID, pWbPath, usrKey, recoveryDat)
        usrKey.deinitialize(count: userKey.count + 1)
        usrKey.deallocate()
        recoveryDat.deinitialize(count: recoveryData.count + 1)
        recoveryDat.deallocate()
        if (pWbData == nil) {
            print("Error! WB initialize failed.")
            return false
        }
        SecureStorage.clearSecureStorage()
        
        let retLength: Int = getDataLength(array: Array(UnsafeBufferPointer(start: pWbData, count: 4)))
        mWbData = Array(UnsafeBufferPointer(start: pWbData, count: retLength))
        if (putStringSharedPreference(key: PREFERENCE_WB, value: byteArrayToHexString(byteArray: mWbData!)) == false) {
            print("Error! WB secure save failed.")
            return false
        }
        
        return true
    }
    
    public func byteArrayToHexString(byteArray: Array<UInt8>) -> String {
        let hexDigits = Array("0123456789ABCDEF".utf16)
        var chars: [unichar] = []
        chars.reserveCapacity(2 * byteArray.count)
        for byte in byteArray {
            chars.append(hexDigits[Int(byte / 16)])
            chars.append(hexDigits[Int(byte % 16)])
        }
        return String(utf16CodeUnits: chars, count: chars.count)
    }
    
    public func hexStringToByteArray(hexString: String) -> Array<UInt8>? {
        let length = hexString.count
        if length & 1 != 0 {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length/2)
        var index = hexString.startIndex
        for _ in 0..<length/2 {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let b = UInt8(hexString[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
}
