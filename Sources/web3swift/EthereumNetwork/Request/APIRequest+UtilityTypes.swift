//
//  APIRequest+UtilityTypes.swift
//
//
//  Created by Yaroslav Yashin on 12.07.2022.
//

import Foundation

/// JSON RPC response structure for serialization and deserialization purposes.
public struct APIResponse<Result>: Decodable where Result: APIResultType {
    public var id: Int
    public var jsonrpc = "2.0"
    public var result: Result
    
    public init(id: Int, jsonrpc: String = "2.0", result: Result) {
        self.id = id
        self.jsonrpc = jsonrpc
        self.result = result
    }
}

public enum REST: String {
    case POST
    case GET
}

public struct RequestBody: Encodable {
    var jsonrpc = "2.0"
    var id = Counter.increment()

    var method: String
    var params: [RequestParameter]
}
