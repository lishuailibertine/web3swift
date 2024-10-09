//
//  ABIEncoderTest.swift
//  Tests
//
//  Created by JeneaVranceanu on 28/03/2022.
//  Copyright © 2022 web3swift. All rights reserved.
//

import Foundation
import Secp256k1Swift
import XCTest
import BigInt
@testable import web3swift

class ABIEncoderTest: XCTestCase {

    func testEncodeInt() {
        XCTAssertEqual(ABIEncoder.encodeSingleType(type: .int(bits: 32), value: -10 as AnyObject)?.toHexString(), "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6")
        XCTAssertEqual(ABIEncoder.encodeSingleType(type: .int(bits: 32), value: 10 as AnyObject)?.toHexString(), "000000000000000000000000000000000000000000000000000000000000000a")
    }

    func testEncodeUInt() {
        XCTAssertEqual(ABIEncoder.encodeSingleType(type: .uint(bits: 32), value: -10 as AnyObject), nil)
        XCTAssertEqual(ABIEncoder.encodeSingleType(type: .uint(bits: 32), value: 10 as AnyObject)?.toHexString(), "000000000000000000000000000000000000000000000000000000000000000a")
    }
    func testContractCreatePacked() {
        let sender = EthereumAddress("0xBF85582f17e04E7E37EeEBBd8e7c993587F58932")!
        let address = EthereumAddress.create(sender: sender, nonce: BigUInt(1))
        XCTAssert("0x8E469c85A587D615bF483691976D792c2749E474" == address.address)
    }
    
    func testEncodeAndEncodePacked() {
        let owner = EthereumAddress("0x4d4e47f4a0556fec5c2413ad47d58f46336f63d1")!
        let factory = EthereumAddress("0x1A85a1fdA882dbcC9Bcc1aE589b795edAb71A12C")!
        let creationCode = Data(hex: "608060405260405162000c5138038062000c51833981810160405281019062000029919062000580565b6200003d828260006200004560201b60201c565b5050620007d7565b62000056836200008860201b60201c565b600082511180620000645750805b156200008357620000818383620000df60201b620000371760201c565b505b505050565b62000099816200011560201b60201c565b8073ffffffffffffffffffffffffffffffffffffffff167fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b60405160405180910390a250565b60606200010d838360405180606001604052806027815260200162000c2a60279139620001eb60201b60201c565b905092915050565b6200012b816200027d60201b620000641760201c565b6200016d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040162000164906200066d565b60405180910390fd5b80620001a77f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b620002a060201b620000871760201c565b60000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60606000808573ffffffffffffffffffffffffffffffffffffffff1685604051620002179190620006dc565b600060405180830381855af49150503d806000811462000254576040519150601f19603f3d011682016040523d82523d6000602084013e62000259565b606091505b50915091506200027286838387620002aa60201b60201c565b925050509392505050565b6000808273ffffffffffffffffffffffffffffffffffffffff163b119050919050565b6000819050919050565b606083156200031a5760008351036200031157620002ce856200027d60201b60201c565b62000310576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401620003079062000745565b60405180910390fd5b5b8290506200032d565b6200032c83836200033560201b60201c565b5b949350505050565b600082511115620003495781518083602001fd5b806040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016200037f9190620007b3565b60405180910390fd5b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000620003c9826200039c565b9050919050565b620003db81620003bc565b8114620003e757600080fd5b50565b600081519050620003fb81620003d0565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b62000456826200040b565b810181811067ffffffffffffffff821117156200047857620004776200041c565b5b80604052505050565b60006200048d62000388565b90506200049b82826200044b565b919050565b600067ffffffffffffffff821115620004be57620004bd6200041c565b5b620004c9826200040b565b9050602081019050919050565b60005b83811015620004f6578082015181840152602081019050620004d9565b60008484015250505050565b6000620005196200051384620004a0565b62000481565b90508281526020810184848401111562000538576200053762000406565b5b62000545848285620004d6565b509392505050565b600082601f83011262000565576200056462000401565b5b81516200057784826020860162000502565b91505092915050565b600080604083850312156200059a576200059962000392565b5b6000620005aa85828601620003ea565b925050602083015167ffffffffffffffff811115620005ce57620005cd62000397565b5b620005dc858286016200054d565b9150509250929050565b600082825260208201905092915050565b7f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60008201527f6f74206120636f6e747261637400000000000000000000000000000000000000602082015250565b600062000655602d83620005e6565b91506200066282620005f7565b604082019050919050565b60006020820190508181036000830152620006888162000646565b9050919050565b600081519050919050565b600081905092915050565b6000620006b2826200068f565b620006be81856200069a565b9350620006d0818560208601620004d6565b80840191505092915050565b6000620006ea8284620006a5565b915081905092915050565b7f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000600082015250565b60006200072d601d83620005e6565b91506200073a82620006f5565b602082019050919050565b6000602082019050818103600083015262000760816200071e565b9050919050565b600081519050919050565b60006200077f8262000767565b6200078b8185620005e6565b93506200079d818560208601620004d6565b620007a8816200040b565b840191505092915050565b60006020820190508181036000830152620007cf818462000772565b905092915050565b61044380620007e76000396000f3fe6080604052366100135761001161001d565b005b61001b61001d565b005b610025610091565b610035610030610093565b6100a2565b565b606061005c83836040518060600160405280602781526020016103e7602791396100c8565b905092915050565b6000808273ffffffffffffffffffffffffffffffffffffffff163b119050919050565b6000819050919050565b565b600061009d61014e565b905090565b3660008037600080366000845af43d6000803e80600081146100c3573d6000f35b3d6000fd5b60606000808573ffffffffffffffffffffffffffffffffffffffff16856040516100f291906102db565b600060405180830381855af49150503d806000811461012d576040519150601f19603f3d011682016040523d82523d6000602084013e610132565b606091505b5091509150610143868383876101a5565b925050509392505050565b600061017c7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b610087565b60000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b606083156102075760008351036101ff576101bf85610064565b6101fe576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101f59061034f565b60405180910390fd5b5b829050610212565b610211838361021a565b5b949350505050565b60008251111561022d5781518083602001fd5b806040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161026191906103c4565b60405180910390fd5b600081519050919050565b600081905092915050565b60005b8381101561029e578082015181840152602081019050610283565b60008484015250505050565b60006102b58261026a565b6102bf8185610275565b93506102cf818560208601610280565b80840191505092915050565b60006102e782846102aa565b915081905092915050565b600082825260208201905092915050565b7f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000600082015250565b6000610339601d836102f2565b915061034482610303565b602082019050919050565b600060208201905081810360008301526103688161032c565b9050919050565b600081519050919050565b6000601f19601f8301169050919050565b60006103968261036f565b6103a081856102f2565b93506103b0818560208601610280565b6103b98161037a565b840191505092915050565b600060208201905081810360008301526103de818461038b565b90509291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a26469706673582212208778d4f2f83817b945ec6f3a9766ff9ffc84732a5060f46c4a44a17fb223ea9264736f6c63430008120033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564")
        let initCode = ABIEncoder.encodePacked(
            types: [
                .dynamicBytes,
                .dynamicBytes
            ],
            values: [
                creationCode,
                ABIEncoder.encode(
                    types: [
                        .address,
                        .dynamicBytes
                    ],
                    values: [
                        EthereumAddress.create(sender: factory, nonce: BigUInt(1)),
                        ABIEncoder.encodeCall(
                            name: "initialize",
                            types: [
                                .address
                            ],
                            values: [
                                owner
                            ]
                        )!
                    ] as! [Any])!
            ] as! [Any]
        )
        let salt = Data(repeating: 0, count: 32)
        XCTAssert(EthereumAddress.create2(factory: factory, salt: salt, initCode: initCode!) == EthereumAddress("0xc358bf7ce2091ffd2624e934a8379cdb37594990")!)
    }

    func testSoliditySha3() throws {
        var hex = try ABIEncoder.soliditySha3(true).toHexString().addHexPrefix()
        assert(hex == "0x5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2")
        hex = try ABIEncoder.soliditySha3(-10).toHexString().addHexPrefix()
        assert(hex == "0xd6fb717f7e270a360f5093ce6a7a3752183e89c9a9afe5c0cb54b458a304d3d5")
        hex = try ABIEncoder.soliditySha3(Data.fromHex("0xfff23243")!).toHexString().addHexPrefix()
        assert(hex == "0x0ee4597224d3499c72aa0c309b0d0cb80ff3c2439a548c53edb479abfd6927ba")
        hex = try ABIEncoder.soliditySha3(UInt(234564535)).toHexString().addHexPrefix()
        assert(hex == "0xb2daf574dc6ceac97e984c8a3ffce3c1ec19e81cc6b18aeea67b3ac2666f4e97")

        hex = try ABIEncoder.soliditySha3([UInt(234564535), Data.fromHex("0xfff23243")!, true, -10]).toHexString().addHexPrefix()
        assert(hex == "0x3e27a893dc40ef8a7f0841d96639de2f58a132be5ae466d40087a2cfa83b7179")

        hex = try ABIEncoder.soliditySha3("Hello!%").toHexString().addHexPrefix()
        assert(hex == "0x661136a4267dba9ccdf6bfddb7c00e714de936674c4bdb065a531cf1cb15c7fc")

        // This is not JS. '234' (with single or double quotes) will be a String, not any kind of number.
        // From Web3JS docs:> web3.utils.soliditySha3('234'); // auto detects: uint256

        hex = try ABIEncoder.soliditySha3(0xea).toHexString().addHexPrefix()
        assert(hex == "0x61c831beab28d67d1bb40b5ae1a11e2757fa842f031a2d0bc94a7867bc5d26c2")

        hex = try ABIEncoder.soliditySha3(234).toHexString().addHexPrefix()
        assert(hex == "0x61c831beab28d67d1bb40b5ae1a11e2757fa842f031a2d0bc94a7867bc5d26c2")

        hex = try ABIEncoder.soliditySha3(UInt64(234)).toHexString().addHexPrefix()
        assert(hex == "0x6e48b7f8b342032bfa46a07cf85358feee0efe560d6caa87d342f24cdcd07b0c")

        hex = try ABIEncoder.soliditySha3(UInt(234)).toHexString().addHexPrefix()
        assert(hex == "0x61c831beab28d67d1bb40b5ae1a11e2757fa842f031a2d0bc94a7867bc5d26c2")

        hex = try ABIEncoder.soliditySha3("0x407D73d8a49eeb85D32Cf465507dd71d507100c1").toHexString().addHexPrefix()
        assert(hex == "0x4e8ebbefa452077428f93c9520d3edd60594ff452a29ac7d2ccc11d47f3ab95b")

        hex = try ABIEncoder.soliditySha3(Data.fromHex("0x407D73d8a49eeb85D32Cf465507dd71d507100c1")!).toHexString().addHexPrefix()
        assert(hex == "0x4e8ebbefa452077428f93c9520d3edd60594ff452a29ac7d2ccc11d47f3ab95b")

        hex = try ABIEncoder.soliditySha3(EthereumAddress("0x407D73d8a49eeb85D32Cf465507dd71d507100c1")!).toHexString().addHexPrefix()
        assert(hex == "0x4e8ebbefa452077428f93c9520d3edd60594ff452a29ac7d2ccc11d47f3ab95b")

        hex = try ABIEncoder.soliditySha3("Hello!%").toHexString().addHexPrefix()
        assert(hex == "0x661136a4267dba9ccdf6bfddb7c00e714de936674c4bdb065a531cf1cb15c7fc")

        hex = try ABIEncoder.soliditySha3(Int8(-23)).toHexString().addHexPrefix()
        assert(hex == "0xdc046d75852af4aea44a770057190294068a953828daaaab83800e2d0a8f1f35")

        hex = try ABIEncoder.soliditySha3(EthereumAddress("0x85F43D8a49eeB85d32Cf465507DD71d507100C1d")!).toHexString().addHexPrefix()
        assert(hex == "0xe88edd4848fdce08c45ecfafd2fbfdefc020a7eafb8178e94c5feaeec7ac0bb4")

        hex = try ABIEncoder.soliditySha3(["Hello!%", Int8(-23), EthereumAddress("0x85F43D8a49eeB85d32Cf465507DD71d507100C1d")!]).toHexString().addHexPrefix()
        assert(hex == "0xa13b31627c1ed7aaded5aecec71baf02fe123797fffd45e662eac8e06fbe4955")
    }

    func testSoliditySha3FailGivenFloatDouble() throws {
        assert((try? ABIEncoder.soliditySha3(Float(1))) == nil)
        assert((try? ABIEncoder.soliditySha3(Double(1))) == nil)
        assert((try? ABIEncoder.soliditySha3(CGFloat(1))) == nil)
        assert((try? ABIEncoder.soliditySha3([Float(1)])) == nil)
        assert((try? ABIEncoder.soliditySha3([Double(1)])) == nil)
        assert((try? ABIEncoder.soliditySha3([CGFloat(1)])) == nil)
    }

    /// `[AnyObject]` is not allowed to be used directly as input for `solidtySha3`.
    /// `AnyObject` erases type data making it impossible to encode some types correctly,
    /// e.g.: Bool can be treated as Int (8/16/32/64) and 0/1 numbers can be treated as Bool.
    func testSoliditySha3FailGivenArrayWithEmptyString() throws {
        var didFail = false
        do {
            _ = try ABIEncoder.soliditySha3([""] as [AnyObject])
        } catch {
            didFail = true
        }
        XCTAssertTrue(didFail)
    }

    /// `AnyObject` is not allowed to be used directly as input for `solidtySha3`.
    /// `AnyObject` erases type data making it impossible to encode some types correctly,
    /// e.g.: Bool can be treated as Int (8/16/32/64) and 0/1 numbers can be treated as Bool.
    func testSoliditySha3FailGivenEmptyString() throws {
        var didFail = false
        do {
            _ = try ABIEncoder.soliditySha3("" as AnyObject)
        } catch {
            didFail = true
        }
        XCTAssertTrue(didFail)
    }

    func testAbiEncodingEmptyValues() {
        let zeroBytes = ABIEncoder.encode(types: [ABI.Element.InOut](), values: [Any]())!
        XCTAssert(zeroBytes.count == 0)

        let functionWithNoInput = ABI.Element.Function(name: "testFunction",
                                                       inputs: [],
                                                       outputs: [],
                                                       constant: false,
                                                       payable: false)
        let encodedFunction = functionWithNoInput.encodeParameters([])
        XCTAssertTrue(functionWithNoInput.methodEncoding == encodedFunction)
        XCTAssertTrue("0xe16b4a9b" == encodedFunction?.toHexString().addHexPrefix().lowercased())
    }

    func testConvertToBigInt() {
        XCTAssertEqual(ABIEncoder.convertToBigInt(BigInt(-29390909).serialize()), -29390909)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Data.fromHex("00FF")!), 255)
        XCTAssertEqual(ABIEncoder.convertToBigInt(BigInt(-29390909)), -29390909)
        XCTAssertEqual(ABIEncoder.convertToBigInt(BigUInt(29390909)), 29390909)
        XCTAssertEqual(ABIEncoder.convertToBigInt(UInt(123)), 123)
        XCTAssertEqual(ABIEncoder.convertToBigInt(UInt8(254)), 254)
        XCTAssertEqual(ABIEncoder.convertToBigInt(UInt16(9090)), 9090)
        XCTAssertEqual(ABIEncoder.convertToBigInt(UInt32(747474)), 747474)
        XCTAssertEqual(ABIEncoder.convertToBigInt(UInt64(45222)), 45222)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int(123)), 123)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int8(127)), 127)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int16(9090)), 9090)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int32(83888)), 83888)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int64(45222)), 45222)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int(-32213)), -32213)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int8(-10)), -10)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int16(-32000)), -32000)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int32(-50050500)), -50050500)
        XCTAssertEqual(ABIEncoder.convertToBigInt(Int64(-2)), -2)
        XCTAssertEqual(ABIEncoder.convertToBigInt("10"), 10)
        XCTAssertEqual(ABIEncoder.convertToBigInt("-10"), -10)
        XCTAssertEqual(ABIEncoder.convertToBigInt("FF"), 255)
        XCTAssertEqual(ABIEncoder.convertToBigInt("-FF"), -255)
        XCTAssertEqual(ABIEncoder.convertToBigInt("0xFF"), 255)
        XCTAssertEqual(ABIEncoder.convertToBigInt("    10  "), 10)
        XCTAssertEqual(ABIEncoder.convertToBigInt("  -10 "), -10)
        XCTAssertEqual(ABIEncoder.convertToBigInt(" FF   "), 255)
        XCTAssertEqual(ABIEncoder.convertToBigInt(" -FF   "), -255)
        XCTAssertEqual(ABIEncoder.convertToBigInt(" 0xFF    "), 255)
    }

    func testConvertToBigUInt() {
        /// When negative value is serialized the first byte represents sign when decoding as a signed number.
        /// Unsigned numbers treat the first byte as just another byte of a number, not a sign.
        XCTAssertEqual(ABIEncoder.convertToBigUInt(BigInt(-29390909).serialize()), 4324358205)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Data.fromHex("00FF")!), 255)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(BigInt(-29390909)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(BigUInt(29390909)), 29390909)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(UInt(123)), 123)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(UInt8(254)), 254)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(UInt16(9090)), 9090)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(UInt32(747474)), 747474)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(UInt64(45222)), 45222)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int(123)), 123)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int8(127)), 127)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int16(9090)), 9090)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int32(83888)), 83888)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int64(45222)), 45222)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int(-32213)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int8(-10)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int16(-32000)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int32(-50050500)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(Int64(-2)), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("10"), 10)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("-10"), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("FF"), 255)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("-FF"), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("0xFF"), 255)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("    10  "), 10)
        XCTAssertEqual(ABIEncoder.convertToBigUInt("  -10 "), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(" FF   "), 255)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(" -FF   "), nil)
        XCTAssertEqual(ABIEncoder.convertToBigUInt(" 0xFF    "), 255)
    }

    /// When dynamic types (string, non-fixed size array, dynamic bytes) are encoded
    /// they include a special 32 bytes entry called data offset that hold the value telling
    /// how much bytes should be skipped from the beginning of the resulting byte array to reach the
    /// value of the dynamic type.
    func testDynamicTypesDataOffset() {
        var hexData = ABIEncoder.encode(types: [.string], values: ["test"])?.toHexString()
        XCTAssertEqual(hexData?[0..<64], "0000000000000000000000000000000000000000000000000000000000000020")
        XCTAssertEqual(hexData, "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000")
        hexData = ABIEncoder.encode(types: [.array(type: .uint(bits: 8), length: 0)], values: [[1, 2, 3, 4]])?.toHexString()
        XCTAssertEqual(hexData?[0..<64], "0000000000000000000000000000000000000000000000000000000000000020")
        XCTAssertEqual(hexData, "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004")

        // This one shouldn't have data offset
        hexData = ABIEncoder.encode(types: [.array(type: .uint(bits: 8), length: 4)], values: [[1, 2, 3, 4]])?.toHexString()
        // First 32 bytes are the first value from the array
        XCTAssertEqual(hexData?[0..<64], "0000000000000000000000000000000000000000000000000000000000000001")
        XCTAssertEqual(hexData, "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004")

        let types: [ABI.Element.ParameterType] = [.uint(bits: 8),
                                                  .bool,
                                                  .array(type: .uint(bits: 8), length: 0),
                                                  .bytes(length: 2)]
        let values: [Any] = [10, false, [1, 2, 3, 4], Data(count: 2)]
        hexData = ABIEncoder.encode(types: types, values: values)?.toHexString()
        XCTAssertEqual(hexData?[128..<192], "0000000000000000000000000000000000000000000000000000000000000080")
        XCTAssertEqual(hexData, "000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004")
    }

    /// Test for the expected output when encoding dynamic types.
    func testAbiEncodingDynamicTypes() {
        var encodedValue = ABIEncoder.encode(types: [.dynamicBytes], values: [Data.fromHex("6761766f66796f726b")!])!.toHexString()
        XCTAssertEqual(encodedValue, "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000096761766f66796f726b0000000000000000000000000000000000000000000000")

        encodedValue = ABIEncoder.encode(types: [.dynamicBytes], values: [Data.fromHex("731a3afc00d1b1e3461b955e53fc866dcf303b3eb9f4c16f89e388930f48134b")!])!.toHexString()
        XCTAssertEqual(encodedValue, "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020731a3afc00d1b1e3461b955e53fc866dcf303b3eb9f4c16f89e388930f48134b")

        encodedValue = ABIEncoder.encode(types: [.dynamicBytes], values: [Data.fromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1")!])!.toHexString()
        XCTAssertEqual(encodedValue, "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000009ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff100")

        encodedValue = ABIEncoder.encode(types: [.dynamicBytes], values: [Data.fromHex("c3a40000c3a4")!])!.toHexString()
        XCTAssertEqual(encodedValue, "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006c3a40000c3a40000000000000000000000000000000000000000000000000000")

        encodedValue = ABIEncoder.encode(types: [.string], values: ["gavofyork"])!.toHexString()
        XCTAssertEqual(encodedValue, "000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000096761766f66796f726b0000000000000000000000000000000000000000000000")

        encodedValue = ABIEncoder.encode(types: [.string], values: ["Heeäööä👅D34ɝɣ24Єͽ-.,äü+#/"])!.toHexString()
        XCTAssertEqual(encodedValue, "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000026486565c3a4c3b6c3b6c3a4f09f9185443334c99dc9a33234d084cdbd2d2e2cc3a4c3bc2b232f0000000000000000000000000000000000000000000000000000")
    }
}
