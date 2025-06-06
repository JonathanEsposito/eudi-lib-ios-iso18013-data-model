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

import Foundation
import SwiftCBOR
import OrderedCollections
/// Device retrieval mdoc request structure

/// In mDoc holder initialize a ``DeviceRequest`` with incoming CBOR bytes (decoding)
/// ```swift
/// let dr = DeviceRequest(data: bytes)
/// ```

/// In mdoc reader initialize a ``DeviceRequest`` with desired elements to read
/// ```swift
/// let isoKeys: [IsoMdlModel.CodingKeys] = [.familyName, .documentNumber, .drivingPrivileges, .issueDate, .expiryDate, .portrait]
///	let dr3 = DeviceRequest(mdl: isoKeys, agesOver: [18,21], intentToRetain: true)
/// ```
public struct DeviceRequest: Sendable {
	/// The current version
	static let currentVersion = "1.0"
	/// The version requested
    public let version: String
	/// An array of all requested documents.
    public let docRequests: [DocRequest]

    enum Keys: String {
        case version
        case docRequests
    }
}

extension DeviceRequest: CBORDecodable {
    public init?(cbor: CBOR) {
        guard case let .map(m) = cbor else { return nil }
        guard case let .utf8String(v) = m[Keys.version] else { return nil }
        version = v
		if v.count == 0 || v.prefix(1) != "1" { return nil }
        guard case let .array(cdrs) = m[Keys.docRequests] else { return nil }
        let drs = cdrs.compactMap { DocRequest(cbor: $0) }
        guard drs.count > 0 else { return nil }
        docRequests = drs
    }
}

extension DeviceRequest: CBOREncodable {
    public func encode(options: CBOROptions) -> [UInt8] { toCBOR(options: options).encode(options: options) }

	public func toCBOR(options: CBOROptions) -> CBOR {
		var m = OrderedDictionary<CBOR, CBOR>()
        m[.utf8String(Keys.version.rawValue)] = .utf8String(version)
        m[.utf8String(Keys.docRequests.rawValue)] = .array(docRequests.map { $0.toCBOR(options: options) })
		return .map(m)
	}
}

extension DeviceRequest {
    /// Initialize mDoc request
    /// - Parameters:
    ///   - items: Iso specified elements to request
    ///   - agesOver: Ages to request if equal or above
    ///   - intentToRetain: Specify intent to retain (after retrieval)
	public init(mdl items: [IsoMdlModel.CodingKeys], agesOver: [Int], intentToRetain: IntentToRetain = true) {
        let itemsElements = items.map { ElementToRequest(nameSpace: IsoMdlModel.isoNamespace,
                                                         elementId: $0.rawValue,
                                                         intentToRetain: intentToRetain) }
        
        let agesOverElements = agesOver.map { ElementToRequest(nameSpace: IsoMdlModel.isoNamespace,
                                                               elementId: "age_over_\($0)",
                                                               intentToRetain: intentToRetain) }
        
        self.init(version: "1.0", documents: [DocumentRequest(docType: IsoMdlModel.isoDocType,
                                                              elements: itemsElements + agesOverElements)])
	}
    
    public init(version: String, documents: [DocumentRequest]) {
        self.version = version
        self.docRequests = documents.map { $0.docRequest }
    }
    
}

public struct DocumentRequest {
    let docType: DocType
    let elements: [ElementToRequest]
    let requestInfo: [String: Any]
    
    var docRequest: DocRequest {
        DocRequest(itemsRequest: itemsRequest, itemsRequestRawData: nil, readerAuth: nil, readerAuthRawCBOR: nil)
    }
    
    private var itemsRequest: ItemsRequest {
        let elementsPerNameSpace = Dictionary(grouping: elements, by: \.nameSpace)
        
        let dataElementsPerNameSpaces = elementsPerNameSpace.mapValues {
            RequestDataElements(dataElements: $0.reduce(into: [DataElementIdentifier: IntentToRetain]()) { $0[$1.elementId] = $1.intentToRetain })
        }
        
        return ItemsRequest(docType: docType,
                            requestNameSpaces: RequestNameSpaces(nameSpaces: dataElementsPerNameSpaces),
                            requestInfo: nil)
    }
    
    public init(docType: String, elements: [ElementToRequest], requestInfo: [String: Any] = [:]) {
        self.docType = docType
        self.elements = elements
        self.requestInfo = requestInfo
    }
}

public struct ElementToRequest {
    let nameSpace: NameSpace
    let elementId: DataElementIdentifier
    let intentToRetain: IntentToRetain
    
    public init(nameSpace: NameSpace, elementId: DataElementIdentifier, intentToRetain: IntentToRetain) {
        self.nameSpace = nameSpace
        self.elementId = elementId
        self.intentToRetain = intentToRetain
    }
}
