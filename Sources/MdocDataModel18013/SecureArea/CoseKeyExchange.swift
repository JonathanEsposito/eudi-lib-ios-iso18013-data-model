//
//  File.swift
//  MdocDataModel18013
//
//  Created by Jonathan Esposito on 20/05/2025.
//

import Foundation
import CryptoKit

/// A COSE_Key exchange pair
public struct CoseKeyExchange {
    public let publicKey: CoseKey
    public var privateKey: WalletPrivateKey
    
    public init(publicKey: CoseKey, privateKey: WalletPrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}
