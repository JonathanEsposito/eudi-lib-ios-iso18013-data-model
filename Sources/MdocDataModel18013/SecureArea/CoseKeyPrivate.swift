/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#if canImport(CryptoKit)
import CryptoKit
#else 
import Crypto
#endif 
import Foundation
import SwiftCBOR

enum CoseKeyPrivateError: Error {
    case unsupportedCurve
}

/// COSE_Key + private key
public struct CoseKeyPrivate: Sendable, Equatable {
    public let crv: CoseEcCurve
    public var key: CoseKey
    public var d: [UInt8]
}

// MARK: - Init's

extension CoseKeyPrivate {
    // make new key // TODO: only for KeyAgreement?
    public init(crv: CoseEcCurve) {
        var privateKeyx963Data: Data
        switch crv {
        case .P256:
            let key = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            privateKeyx963Data = key.x963Representation
        case .P384:
            let key = P384.KeyAgreement.PrivateKey(compactRepresentable: false)
            privateKeyx963Data = key.x963Representation
        case .P521:
            let key = P521.KeyAgreement.PrivateKey(compactRepresentable: false)
            privateKeyx963Data = key.x963Representation
        default: fatalError("Unsupported curve type \(crv)")
        }
        self.init(privateKeyx963Data: privateKeyx963Data, crv: crv)
    }
    
    public init(privateKeyx963Data: Data, crv: CoseEcCurve = .P256) {
        let xyk = privateKeyx963Data.advanced(by: 1)
        let klen = xyk.count / 3
        let xdata: Data = Data(xyk[0..<klen])
        let ydata: Data = Data(xyk[klen..<2 * klen])
        let ddata: Data = Data(xyk[2 * klen..<3 * klen])
        key = CoseKey(crv: crv, x: xdata.bytes, y: ydata.bytes)
        d = ddata.bytes
        self.crv = crv
    }
    
}

extension CoseKeyPrivate {
    
    // decode cbor string
    public init?(base64: String) {
        guard let d = Data(base64Encoded: base64),
              let obj = try? CBOR.decode([UInt8](d)),
              let coseKey = CoseKey(cbor: obj),
              let cd = obj[-4],
              case let CBOR.byteString(rd) = cd else { return nil }
        self.init(key: coseKey, d: rd)
    }
    
    private init(key: CoseKey, d: [UInt8]) {
        self.key = key
        self.d = d
        self.crv = key.crv
    }
    
}

// MARK: - Methods

extension CoseKeyPrivate {
    /// An ANSI x9.63 representation of the private key.
    public func getx963Representation() -> Data {
        let keyData = NSMutableData(bytes: [0x04], length: [0x04].count)
        keyData.append(Data(key.x))
        keyData.append(Data(key.y))
        keyData.append(Data(d))
        return keyData as Data
    }
}
