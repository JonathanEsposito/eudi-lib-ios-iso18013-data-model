//
//  P384EncryptionKey.swift
//  BDIW
//
//  Created by Jonathan Esposito on 21/05/2025.
//  Copyright © 2025 AppFoundry. All rights reserved.
//

import Foundation
import CryptoKit

struct P384EncryptionKey: WalletEncryptionKey {
    
    let curve: CoseEcCurve = .P384
    let privateKey: P384.KeyAgreement.PrivateKey
    var privateKeyDataRepresentation: Data { privateKey.rawRepresentation }
    var publicKey: P384.KeyAgreement.PublicKey { privateKey.publicKey }
    var publicKeyDer: Data { publicKey.derRepresentation }
    var publicKeyX963: Data { publicKey.x963Representation }
    var publicKeyString: String { publicKey.derRepresentation.base64EncodedString() }
    
    init() {
        privateKey = P384.KeyAgreement.PrivateKey()
    }
    
    init(dataRepresentation: Data) throws {
        privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: dataRepresentation)
    }
    
    init(x963Representation: Data) throws {
        privateKey = try P384.KeyAgreement.PrivateKey(x963Representation: x963Representation)
    }
    
    func sharedSecretFromKeyAgreement(withX963 x963Data: Data) throws -> SharedSecret {
        let remotePublicKey = try P384.KeyAgreement.PublicKey(x963Representation: x963Data)
        return try privateKey.sharedSecretFromKeyAgreement(with: remotePublicKey)
    }
    
}

extension P384EncryptionKey {
    
    func encrypt(_ dataToBeEncrypted: Data, remotePublicKeyDer: Data) throws -> Data? {
        let counterpartPublicKey = try P384.KeyAgreement.PublicKey(derRepresentation: remotePublicKeyDer)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: counterpartPublicKey)
        let key = sharedSecret.x963DerivedSymmetricKey(using: SHA384.self,
                                                       sharedInfo: remotePublicKeyDer + privateKey.publicKey.derRepresentation,
                                                       outputByteCount: 48)
        
        let sealedBox = try AES.GCM.seal(dataToBeEncrypted, using: key)
        
        return sealedBox.combined
    }
    
    func decrypt(_ encryptedData: Data, remotePublicKeyDer: Data) throws -> Data {
        let counterpartPublicKey = try P384.KeyAgreement.PublicKey(derRepresentation: remotePublicKeyDer)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: counterpartPublicKey)
        let key = sharedSecret.x963DerivedSymmetricKey(using: SHA384.self,
                                                       sharedInfo: privateKey.publicKey.derRepresentation + remotePublicKeyDer,
                                                       outputByteCount: 48)
        
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        
        return decryptedData
    }
    
    func hkdfDerivedSymmetricKey(salt: [UInt8], publicKey: Data, sharedInfo: Data) throws -> SymmetricKey {
        let publicKeyShare = try P384.KeyAgreement.PublicKey(x963Representation: publicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKeyShare)
        return sharedSecret.hkdfDerivedSymmetricKey(using: SHA384.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 48)
    }
    
}

