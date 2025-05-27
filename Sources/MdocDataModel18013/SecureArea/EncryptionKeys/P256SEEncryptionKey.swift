//
//  P256SEEncryptionKey.swift
//  BDIW
//
//  Created by Jonathan Esposito on 21/05/2025.
//  Copyright © 2025 AppFoundry. All rights reserved.
//

import Foundation
import CryptoKit
import LocalAuthentication // For LAContext
import Security // For SecAccessControl

struct P256SEEncryptionKey: WalletEncryptionKey {
    
    let curve: CoseEcCurve = .P256
    let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    var privateKeyDataRepresentation: Data { privateKey.dataRepresentation }
    var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }
    var publicKeyDer: Data { publicKey.derRepresentation }
    var publicKeyX963: Data { publicKey.x963Representation }
    var publicKeyString: String { publicKey.derRepresentation.base64EncodedString() }
    
    init() throws {
        let authContext = LAContext()
        
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil)!
        
        self.privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl, authenticationContext: authContext)
    }
    
    init(dataRepresentation: Data) throws {
        let authContext = LAContext()
        
        self.privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: authContext)
    }
    
    func sharedSecretFromKeyAgreement(withX963 x963Data: Data) throws -> SharedSecret {
        let puk256 = try P256.KeyAgreement.PublicKey(x963Representation: x963Data)
        return try privateKey.sharedSecretFromKeyAgreement(with: puk256)
    }
    
}

extension P256SEEncryptionKey {
    
    func encrypt(_ dataToBeEncrypted: Data, remotePublicKeyDer: Data) throws -> Data? {
        let counterpartPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: remotePublicKeyDer)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: counterpartPublicKey)
        let key = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self,
                                                       sharedInfo: remotePublicKeyDer + privateKey.publicKey.derRepresentation,
                                                       outputByteCount: 32)
        
        let sealedBox = try AES.GCM.seal(dataToBeEncrypted, using: key)
        
        return sealedBox.combined
    }
    
    func decrypt(_ encryptedData: Data, remotePublicKeyDer: Data) throws -> Data {
        let counterpartPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: remotePublicKeyDer)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: counterpartPublicKey)
        let key = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self,
                                                       sharedInfo: privateKey.publicKey.derRepresentation + remotePublicKeyDer,
                                                       outputByteCount: 32)
        
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        
        return decryptedData
    }
    
    func hkdfDerivedSymmetricKey(salt: [UInt8], publicKey: Data, sharedInfo: Data) throws -> SymmetricKey {
        let publicKeyShare = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKeyShare)
        return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: sharedInfo, outputByteCount: 32)
    }
    
}
