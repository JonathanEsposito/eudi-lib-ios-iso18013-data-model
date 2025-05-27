//
//  WalletSigningKey.swift
//  MdocDataModel18013
//
//  Created by Jonathan Esposito on 29/04/2025.
//

import Foundation

public protocol WalletSigningKey {
    var curve: CoseEcCurve { get }
    var privateKeyDataRepresentation: Data { get }
    var publicKeyDer: Data { get }
    var publicKeyX963: Data { get }
    func sign(_ challenge: Data) throws -> Data
    func signature(_ dataToSign: Data) throws -> Data
}

extension WalletSigningKey {
    
    public var publicCoseKey: CoseKey {
        CoseKey(crv: curve, x963Representation: publicKeyX963)
    }
    
}
