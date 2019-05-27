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
        let userKey: String = "553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0"
        let ServerKey: String = "71db7cb1bcfa049c2878f1cf0c34fd3a3b87d68e8e6c1a7a7971bdf3b00b822a5ad846cca500ced86b94b8c37a3ac879a8994005d89ef30d9ae837344c1725b0"
        
        let mTrustSigner = TrustSigner(appID: "Test")
        
        recoveryData = mTrustSigner.getRecoveryData(userKey: userKey, serverKey: ServerKey)
        print("@@@ TrustSigner : Recovery Data = \(String(describing: recoveryData))")
        
        if (mTrustSigner.finishRecoveryData() == true) {
            print("@@@ TrustSigner : Finish Recovery = TRUE")
        } else {
            print("@@@ TrustSigner : Finish Recovery = FALSE")
        }
    }
    
    @IBAction func btn_Set_Recovery_Data(_ sender: Any) {
        var pubKey: String? = nil;
        let org_recoveryData: String = "{\"iv\":\"p2gvnNR3Wh/wTZIVXxjJ/Q==\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"xDqFqIr/0HS2aTNR/S69flmreTGDIukhqc7SVLMTN1Ebe3vImU+uXuCg8WJVyHV7L8/sFc8JiWUl7yyZFbyymHQE7uhzB63Pobe03vaVGAolX0gpUr7vy8Ph92APKa4VjRgbNlcJYr/ax1MHFGlStuPi5/wBSWPmgxNEI6tf2sMkJxRsF4vilif+jv5/x/avkv193J5yiERjdDH03N9rsg==\"}"
        let userKey: String = "553da97a442053022ff753cdbb7246aed6f586875ccfa855008dbb3765933f8b7d5ba430ea82dcf113dcc0bb4c3b9e2432525ac043f3e37a18db693e53671cd0"
        
        let mTrustSigner = TrustSigner(appID: "Test")
        
        if (mTrustSigner.setRecoveryData(userKey: userKey, recoveryData: org_recoveryData) != true) {
            print("@@@ TrustSigner : Error! Recovery Failed.")
        }
        
//        mTrustSigner = TrustSigner(appID: "Test")
        pubKey = mTrustSigner.getAccountPublicKey(coinSymbol: "BTC")
        print("@@@ TrustSigner : BTC Pub Key = \(String(describing: pubKey))")
        
        print("============ ORG =================================================")
        print("Mnemonic : (160) : neither way city bird steak bubble clown enjoy media palm flash give figure consider october display dragon edit razor unfold step traffic salt say")
        print("SEED     : (064) : d13b1c3c54fef76da1457676cf29341dbc4c6369f0c72dd3a63f32293206891875e153da8f7bc434d68fcb82d07e934c34a9fa427fd4edbafecea5c9da587fe6")
        print("BTC Pub  : (111) : xpub6C6ChaNuhHShGwtK3wLm67vpa6W6STaKWhdq7RcwuLCVYaBd2oF34dFubxmQaGLyrrLYkQibuS2RMVvjrrxvh16F8AwSdxdMELKUyFmYgeA")
    }
    
}

