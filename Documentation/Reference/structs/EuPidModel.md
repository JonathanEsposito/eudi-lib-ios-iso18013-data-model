**STRUCT**

# `EuPidModel`

**Contents**

- [Properties](#properties)
  - `response`
  - `devicePrivateKey`
  - `euPidDocType`
  - `docType`
  - `nameSpaces`
  - `title`
  - `family_name`
  - `given_name`
  - `birth_date`
  - `family_name_birth`
  - `given_name_birth`
  - `birth_place`
  - `birth_country`
  - `birth_state`
  - `birth_city`
  - `resident_address`
  - `resident_city`
  - `resident_postal_code`
  - `resident_state`
  - `resident_country`
  - `resident_street`
  - `resident_house_number`
  - `gender`
  - `nationality`
  - `age_in_years`
  - `age_birth_year`
  - `expiry_date`
  - `issuing_authority`
  - `issuance_date`
  - `document_number`
  - `administrative_number`
  - `issuing_country`
  - `issuing_jurisdiction`
  - `ageOverXX`
  - `displayStrings`
  - `displayImages`
  - `pidMandatoryElementKeys`
  - `mandatoryElementKeys`

```swift
public struct EuPidModel: Codable, MdocDecodable
```

## Properties
### `response`

```swift
public var response: DeviceResponse?
```

### `devicePrivateKey`

```swift
public var devicePrivateKey: CoseKeyPrivate?
```

### `euPidDocType`

```swift
public static var euPidDocType: String = "eu.europa.ec.eudiw.pid.1"
```

### `id`

```swift
public var id: String = UUID().uuidString
```

### `createdAt`

```swift
public var createdAt: Date = Date()
```

### `docType`

```swift
public var docType = Self.euPidDocType
```

### `nameSpaces`

```swift
public var nameSpaces: [NameSpace]?
```

### `title`

```swift
public var title = String("eu_pid_doctype_name")
```

### `family_name`

```swift
public let family_name: String?
```

### `given_name`

```swift
public let given_name: String?
```

### `birth_date`

```swift
public let birth_date: String?
```

### `family_name_birth`

```swift
public let family_name_birth: String?
```

### `given_name_birth`

```swift
public let given_name_birth: String?
```

### `birth_place`

```swift
public let birth_place: String?
```

### `birth_country`

```swift
public let birth_country: String?
```

### `birth_state`

```swift
public let birth_state: String?
```

### `birth_city`

```swift
public let birth_city: String?
```

### `resident_address`

```swift
public let resident_address: String?
```

### `resident_city`

```swift
public let resident_city: String?
```

### `resident_postal_code`

```swift
public let resident_postal_code: String?
```

### `resident_state`

```swift
public let resident_state: String?
```

### `resident_country`

```swift
public let resident_country: String?
```

### `resident_street`

```swift
public let resident_street: String?
```

### `resident_house_number`

```swift
public let resident_house_number:String?
```

### `gender`

```swift
public let gender: UInt64?
```

### `nationality`

```swift
public let nationality: String?
```

### `age_in_years`

```swift
public let age_in_years: UInt64?
```

### `age_birth_year`

```swift
public let age_birth_year: UInt64?
```

### `expiry_date`

```swift
public let expiry_date: String?
```

### `issuing_authority`

```swift
public let issuing_authority: String?
```

### `issuance_date`

```swift
public let issuance_date: String?
```

### `document_number`

```swift
public let document_number: String?
```

### `administrative_number`

```swift
public let administrative_number: String?
```

### `issuing_country`

```swift
public let issuing_country: String?
```

### `issuing_jurisdiction`

```swift
public let issuing_jurisdiction: String?
```

### `ageOverXX`

```swift
public var ageOverXX = [Int: Bool]()
```

### `displayStrings`

```swift
public var displayStrings = [NameValue]()
```

### `displayImages`

```swift
public var displayImages = [NameImage]()
```

### `pidMandatoryElementKeys`

```swift
public static var pidMandatoryElementKeys: [DataElementIdentifier]
```

### `mandatoryElementKeys`

```swift
public var mandatoryElementKeys: [DataElementIdentifier]
```
