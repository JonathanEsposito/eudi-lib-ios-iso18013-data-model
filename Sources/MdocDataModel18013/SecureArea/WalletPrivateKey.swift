//
//  WalletPrivateKey.swift
//  MdocDataModel18013
//
//  Created by Jonathan Esposito on 22/05/2025.
//

import Foundation
public enum WalletPrivateKey {
    case signing(WalletSigningKey)
    case encryption(WalletEncryptionKey)
    
    public var publicCoseKey: CoseKey {
        switch self {
        case .signing(let key): key.publicCoseKey
        case .encryption(let key): key.publicCoseKey
        }
    }
}
