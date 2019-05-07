//
//  ViewController.swift
//  TrustSignerSample
//
//  Created by Seo Minyeol on 17/04/2019.
//  Copyright © 2019 Seo Minyeol. All rights reserved.
//

import UIKit
import TrustSigner

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    @IBAction func btn_Initialize_WB_Data(_ sender: Any) {
        let mTrustSigner = TrustSigner(appID: "Test")
        if (mTrustSigner.initialize(appID: "Test") == false) {
            print("@@@ TrustSigner : Initialize failed!")
        }
    }
    
    @IBAction func btn_Get_Signature_Data(_ sender: Any) {
        let btcHash: String = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c"
        let hashMsg = "5a9c7c2a462741eecf49019528bf979c341c6719bd246f70d712e9f8137b482c"
        var pubKey: String? = nil
        var sigMsg: String? = nil
        
        let mTrustSigner = TrustSigner(appID: "Test")
        
        pubKey = mTrustSigner.getAccountPublicKey(coinSymbol: "BTC")
        print("@@@ TrustSigner : BTC Pub Key = \(String(describing: pubKey))")
        pubKey = mTrustSigner.getAccountPublicKey(coinSymbol: "ETH")
        print("@@@ TrustSigner : ETH Pub Key = \(String(describing: pubKey))")
        pubKey = mTrustSigner.getAccountPublicKey(coinSymbol: "XLM")
        print("@@@ TrustSigner : XLM Pub Key = \(String(describing: pubKey))")
        
        sigMsg = mTrustSigner.getSignatureData(coinSymbol: "BTC", hdDepth: 5, hdChange: 0, hdIndex: 0, hashMessage: btcHash)
        print("@@@ TrustSigner : BTC Sig = \(String(describing: sigMsg))")
        sigMsg = mTrustSigner.getSignatureData(coinSymbol: "ETH", hdDepth: 5, hdChange: 0, hdIndex: 0, hashMessage: hashMsg)
        print("@@@ TrustSigner : ETH Sig = \(String(describing: sigMsg))")
        sigMsg = mTrustSigner.getSignatureData(coinSymbol: "XLM", hdDepth: 3, hdChange: 0, hdIndex: 0, hashMessage: hashMsg)
        print("@@@ TrustSigner : XLM Sig = \(String(describing: sigMsg))")
    }
    
    @IBAction func btn_Get_Recovery_Data(_ sender: Any) {
        var recoveryData: String? = nil
        let userKey: String = "1234567890123456789012345678901234567890123456789012345678901234"
        let ServerKey: String = "1234567890123456789012345678901234567890123456789012345678901234"
        
        let mTrustSigner = TrustSigner(appID: "Test")
        
        recoveryData = mTrustSigner.getRecoveryData(userKey: userKey, serverKey: ServerKey)
        print("@@@ TrustSigner : Recovery Data = \(String(describing: recoveryData))")
    }
    
    @IBAction func btn_Set_Recovery_Data(_ sender: Any) {
        var pubKey: String? = nil;
        let org_recoveryData: String = "{\"iv\":\"p2gvnNR3Wh/wTZIVXxjJ/Q==\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"DUDZOVA9MRONiroYi17saHeqL6Io6XHf7bOcSl+KZ7loQgFWyqd5KEai7etFgf/UuMWCVTXb8ln9B6b/EbrLuYYIKvy4MKZg3Og7+mUXYVWifILNFwLB5Acx1cY/2IQ6/+Q/hpgmTrY8KpOzw5fyV0QafwnaxpXFvFoyZgmJIIXSeZpVSdhedpvoWozcJ97TPydQykjBsJW1jTTL9cBsuA==\"}"
        let userKey: String = "1234567890123456789012345678901234567890123456789012345678901234"
        
        let mTrustSigner = TrustSigner(appID: "Test")
        
        if (mTrustSigner.setRecoveryData(userKey: userKey, recoveryData: org_recoveryData) != true) {
            print("@@@ TrustSigner : Error! Recovery Failed.")
        }
        
//        mTrustSigner = TrustSigner(appID: "Test")
        pubKey = mTrustSigner.getAccountPublicKey(coinSymbol: "BTC")
        print("@@@ TrustSigner : BTC Pub Key = \(String(describing: pubKey))")
        
        print("============ ORG =================================================")
        print("SEED  : (064) : 99590676129caad71b67de55aabcd7efe3fbaa6e1977774a14e07fe2517a65cebf2a5065a627b362302b8e3e6c325a7aeb19f88a674f5bb89c8ac35cd1b5af52")
        print("BTC Pub (111) : xpub661MyMwAqRbcFSLeReY1p1mSdbcPf9my7qQzYms2P5gM19kw3ubeuMDRTSesyC7nHf6ugcycbcGThAzzmT34fFvvYRdx5Ki23ia2wJKiMTb")
    }
    
}

