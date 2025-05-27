//
//  WalletEncryptionKey.swift
//  MdocDataModel18013
//
//  Created by Jonathan Esposito on 29/04/2025.
//

import Foundation
import CryptoKit

public protocol WalletEncryptionKey {
    var curve: CoseEcCurve { get }
    var privateKeyDataRepresentation: Data { get }
    var publicKeyString: String { get }
    var publicKeyDer: Data { get }
    var publicKeyX963: Data { get }
    func encrypt(_ dataToBeEncrypted: Data, remotePublicKeyDer: Data) throws -> Data?
    func decrypt(_ encryptedData: Data, remotePublicKeyDer: Data) throws -> Data
    /// Calculate the ephemeral MAC key, by performing ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman)
    func hkdfDerivedSymmetricKey(salt: [UInt8], publicKey: Data, sharedInfo: Data) throws -> SymmetricKey
}

extension WalletEncryptionKey {
    
    public var publicCoseKey: CoseKey {
        CoseKey(crv: curve, x963Representation: publicKeyX963)
    }
    
}
