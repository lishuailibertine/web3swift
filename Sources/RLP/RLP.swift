//
//  RLP.swift
//  SwiftRLP
//
//  Created by Alex Vlasov on 04/10/2018.
//  Copyright © 2018 Alex Vlasov. All rights reserved.
//

import Foundation
import BigInt

public struct RLP {
    public enum Error: Swift.Error {
        case encodingError
        case decodingError
    }

    public static var length56 = BigUInt(UInt(56))
    public static var lengthMax = (BigUInt(UInt(1)) << 256)

    public static func encode(element: Any?) -> Data? {
        if let string = element as? String {
            return encode(string)
        } else if let data = element as? Data {
            return encode(data)
        } else if let biguint = element as? BigUInt {
            return encode(biguint)
        }
        return nil
    }

    public static func encode(_ string: String) -> Data? {
        if let hexData = Data.fromHex(string) {
            return encode(hexData)
        }
        guard let data = string.data(using: .utf8) else { return nil }
        return encode(data)
    }

    public static func encode(_ number: Int) -> Data? {
        guard number >= 0 else { return nil }
        let uint = UInt(number)
        return encode(uint)
    }

    public static func encode(_ number: UInt) -> Data? {
        let biguint = BigUInt(number)
        return encode(biguint)
    }

    public static func encode(_ number: BigUInt) -> Data? {
        let encoded = number.serialize()
        return encode(encoded)
    }

    public static func encode(_ data: Data) -> Data? {
        if data.count == 1 && data.bytes[0] < UInt8(0x80) {
            return data
        } else {
            guard let length = encodeLength(data.count, offset: UInt8(0x80)) else { return nil }
            var encoded = Data()
            encoded.append(length)
            encoded.append(data)
            return encoded
        }
    }

    public static func encodeLength(_ length: Int, offset: UInt8) -> Data? {
        if length < 0 {
            return nil
        }
        let bigintLength = BigUInt(UInt(length))
        return encodeLength(bigintLength, offset: offset)
    }

    public static func encodeLength(_ length: BigUInt, offset: UInt8) -> Data? {
        if length < length56 {
            let encodedLength = length + BigUInt(UInt(offset))
            guard encodedLength.bitWidth <= 8 else { return nil }
            return encodedLength.serialize()
        } else if length < lengthMax {
            let encodedLength = length.serialize()
            let len = BigUInt(UInt(encodedLength.count))
            guard let prefix = lengthToBinary(len) else { return nil }
            let lengthPrefix = prefix + offset + UInt8(55)
            var encoded = Data([lengthPrefix])
            encoded.append(encodedLength)
            return encoded
        }
        return nil
    }

    public static func lengthToBinary(_ length: BigUInt) -> UInt8? {
        if length == 0 {
            return UInt8(0)
        }
        let divisor = BigUInt(256)
        var encoded = Data()
        guard let prefix = lengthToBinary(length/divisor) else { return nil }
        let suffix = length % divisor

        var prefixData = Data([prefix])
        if prefix == UInt8(0) {
            prefixData = Data()
        }
        let suffixData = suffix.serialize()

        encoded.append(prefixData)
        encoded.append(suffixData)
        guard encoded.count == 1 else { return nil }
        return encoded.bytes[0]
    }

    public static func encode(_ elements: [Any?]) -> Data? {
        var encodedData = Data()
        for e in elements {
            if let encoded = encode(element: e) {
                encodedData.append(encoded)
            } else {
                guard let asArray = e as? [Any] else { return nil }
                guard let encoded = encode(asArray) else { return nil }
                encodedData.append(encoded)
            }
        }
        guard var encodedLength = encodeLength(encodedData.count, offset: UInt8(0xc0)) else { return nil }
        if encodedLength != Data() {
            encodedLength.append(encodedData)
        }
        return encodedLength
    }

    public static func decode(_ raw: String) -> RLPItem? {
        guard let rawData = Data.fromHex(raw) else { return nil }
        return decode(rawData)
    }

    public static func decode(_ raw: Data) -> RLPItem? {
        if raw.count == 0 {
            return RLPItem.noItem
        }
        var outputArray = [RLPItem]()
        var bytesToParse = Data(raw)
        while bytesToParse.count != 0 {
            let (of, dl, t) = decodeLength(bytesToParse)
            guard let offset = of, let dataLength = dl, let type = t else { return nil }
            switch type {
            case .empty:
                break
            case .data:
                guard let slice = try? slice(data: bytesToParse, offset: offset, length: dataLength) else { return nil }
                let data = Data(slice)
                let rlpItem = RLPItem.init(content: .data(data))
                outputArray.append(rlpItem)
            case .list:
                guard let slice = try? slice(data: bytesToParse, offset: offset, length: dataLength) else { return nil }
                guard let inside = decode(Data(slice)) else { return nil }
                switch inside.content {
                case .data:
                    return nil
                default:
                    outputArray.append(inside)
                }
            }
            guard let tail = try? slice(data: bytesToParse, start: offset + dataLength) else { return nil }
            bytesToParse = tail
        }
        return RLPItem.init(content: .list(outputArray, 0, Data(raw)))
    }

    public struct RLPItem {

        public enum UnderlyingType {
            case empty
            case data
            case list
        }

        public enum RLPContent {
            case noItem
            case data(Data)
            indirect case list([RLPItem], Int, Data)
        }

        public var content: RLPContent

        public var isData: Bool {
            switch self.content {
            case .noItem:
                return false
            case .data:
                return true
            case .list:
                return false
            }
        }

        public var isList: Bool {
            switch self.content {
            case .noItem:
                return false
            case .data:
                return false
            case .list:
                return true
            }
        }
        public var count: Int? {
            switch self.content {
            case .noItem:
                return nil
            case .data:
                return nil
            case .list(let list, _, _):
                return list.count
            }
        }

        public subscript(index: Int) -> RLPItem? {
            get {
                guard case .list(let list, _, _) = self.content else { return nil }
                let item = list[index]
                return item
            }
        }

        public var data: Data? {
            return self.getData()
        }

        public func getData() -> Data? {
            if self.isList {
                guard case .list(_, _, let rawContent) = self.content else { return nil }
                return rawContent
            }
            guard case .data(let data) = self.content else { return nil }
            return data
        }

        public static var noItem: RLPItem {
            return RLPItem.init(content: .noItem)
        }
    }

    public static func decodeLength(_ input: Data) -> (offset: BigUInt?, length: BigUInt?, type: RLPItem.UnderlyingType?) {
        do {
            let length = BigUInt(input.count)
            if length == BigUInt(0) {
                return (0, 0, .empty)
            }
            let prefixByte = input[0]
            if prefixByte <= 0x7f {
                return (BigUInt(0), BigUInt(1), .data)
            } else if prefixByte <= 0xb7 && length > BigUInt(prefixByte - 0x80) {
                let dataLength = BigUInt(prefixByte - 0x80)
                return (BigUInt(1), dataLength, .data)
            } else if try prefixByte <= 0xbf && length > BigUInt(prefixByte - 0xb7) && length >  BigUInt(prefixByte - 0xb7) + toBigUInt(slice(data: input, offset: BigUInt(1), length: BigUInt(prefixByte - 0xb7))) {
                let lengthOfLength = BigUInt(prefixByte - 0xb7)
                let dataLength = try toBigUInt(slice(data: input, offset: BigUInt(1), length: BigUInt(prefixByte - 0xb7)))
                return (1 + lengthOfLength, dataLength, .data)
            } else if prefixByte <= 0xf7 && length > BigUInt(prefixByte - 0xc0) {
                let listLen = BigUInt(prefixByte - 0xc0)
                return (1, listLen, .list)
            } else if try prefixByte <= 0xff && length > BigUInt(prefixByte - 0xf7) && length > BigUInt(prefixByte - 0xf7) + toBigUInt(slice(data: input, offset: BigUInt(1), length: BigUInt(prefixByte - 0xf7))) {
                let lengthOfListLength = BigUInt(prefixByte - 0xf7)
                let listLength = try toBigUInt(slice(data: input, offset: BigUInt(1), length: BigUInt(prefixByte - 0xf7)))
                return (1 + lengthOfListLength, listLength, .list)
            } else {
                return (nil, nil, nil)
            }
        } catch {
            return (nil, nil, nil)
        }
    }

    public static func slice(data: Data, offset: BigUInt, length: BigUInt) throws -> Data {
        if BigUInt(data.count) < offset + length {throw Error.encodingError}
        let slice = data[UInt64(offset) ..< UInt64(offset + length)]
        return Data(slice)
    }

    public static func slice(data: Data, start: BigUInt) throws -> Data {
        if BigUInt(data.count) < start {throw Error.encodingError}
        let slice = data[UInt64(start) ..< UInt64(data.count)]
        return Data(slice)
    }

    public static func toBigUInt(_ raw: Data) throws -> BigUInt {
        if raw.count == 0 {
            throw Error.encodingError
        } else if raw.count == 1 {
            return BigUInt.init(raw)
        } else {
            let slice = raw[0 ..< raw.count - 1]
            return try BigUInt(raw[raw.count-1]) + toBigUInt(slice)*256
        }
    }
}

fileprivate extension Data {

    var bytes: [UInt8] {
        return Array(self)
    }
    
    static func fromHex(_ hex: String) -> Data? {
        let string = hex.lowercased().stripHexPrefix()
        let array = [UInt8](hex: string)
        if array.count == 0 {
            if hex == "0x" || hex == "" {
                return Data()
            } else {
                return nil
            }
        }
        return Data(array)
    }
}


fileprivate extension String {
    func stripHexPrefix() -> String {
        if self.hasPrefix("0x") {
            let indexStart = self.index(self.startIndex, offsetBy: 2)
            return String(self[indexStart...])
        }
        return self
    }
}

fileprivate extension Array where Element == UInt8 {
    init(hex: String) {
        self.init()
        self.reserveCapacity(hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                removeAll()
                return
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }

    func toHexString() -> String {
        return `lazy`.reduce("") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            return $0 + s
        }
    }
}
