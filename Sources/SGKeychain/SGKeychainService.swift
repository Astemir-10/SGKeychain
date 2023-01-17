//
//  SGKeychainService.swift
//  
//
//  Created by Astemir Shibzuhov on 1/17/23.
//

import Foundation
import Security

enum SGKeychainAccessabilityOption {
    case afterFirstUnlockThisDeviceOnly(SecAccessControlCreateFlags)
    case whenPasscodeSetThisDeviceOnly(SecAccessControlCreateFlags)

    var value: CFString {
        switch self {
        case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenPasscodeSetThisDeviceOnly:
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }
    
    var flag: SecAccessControlCreateFlags {
        switch self {
        case .afterFirstUnlockThisDeviceOnly(let flag):
            return flag
        case .whenPasscodeSetThisDeviceOnly(let flag):
            return flag
        }
    }
}

enum SGKeychainMatchLimit {
    case one
    case all
    case custom(Int)
    
    var value: Any {
        switch self {
        case .one:
            return kSecMatchLimitOne
        case .all:
            return kSecMatchLimitAll
        case .custom(let int):
            return int
        }
    }
}

enum SGKeychainOption {
    
    // string
    case accessGroup(String)
    case server(String)
    case account(String)
    case useOperationPrompt(String)
    
    // data
    case valueData(Data)
    
    // bool
    case returnAttributes(Bool)
    case returnData(Bool)
    
    // custom option value
    case accessControl(SGKeychainAccessabilityOption)
    case matchLimit(SGKeychainMatchLimit)
    
    var key: CFString {
        switch self {
        case .accessGroup:
            return kSecAttrAccessGroup
        case .server:
            return kSecAttrServer
        case .account:
            return kSecAttrAccount
        case .valueData:
            return kSecValueData
        case .returnAttributes:
            return kSecReturnAttributes
        case .returnData:
            return kSecReturnData
        case .useOperationPrompt:
            return kSecUseOperationPrompt
        case .matchLimit:
            return kSecMatchLimitOne
        case .accessControl:
            return kSecAttrAccessControl
        }
    }

    var value: Any {
        switch self {
        case .accessGroup(let string):
            return string
        case .server(let string):
            return string
        case .account(let string):
            return string
        case .useOperationPrompt(let string):
            return string
        case .valueData(let data):
            return data
        case .returnAttributes(let bool):
            return bool
        case .returnData(let bool):
            return bool
        case .matchLimit(let option):
            return option.value
        case .accessControl(let option):
            return SecAccessControlCreateWithFlags(nil, option.value, option.flag, nil) as Any
        }
    }
}

enum SGKeychainType {
    // kSecClassGenericPassword
    case genericPassword
    
    // kSecClassInternetPassword
    case internetPassword
    
    var key: CFString {
        switch self {
        case .genericPassword:
            return kSecClassGenericPassword
        case .internetPassword:
            return kSecClassInternetPassword
        }
    }
    
}

protocol SGKeychainServiceProtocol {
    func save(type: SGKeychainType, options: [SGKeychainOption])
    func getDictionary(type: SGKeychainType, options: [SGKeychainOption]) -> NSDictionary
    func getString(type: SGKeychainType, options: [SGKeychainOption]) -> String?
    func getData(type: SGKeychainType, options: [SGKeychainOption]) -> Data?
    func delete(type: SGKeychainType, options: [SGKeychainOption])
    func update(type: SGKeychainType, options: [SGKeychainOption], updateOptions: [SGKeychainOption])
}

final class SGKeychainService: SGKeychainServiceProtocol {
    
    func save(type: SGKeychainType, options: [SGKeychainOption]) {
        var query = options.reduce([CFString: Any]()) { dict, option in
            var dict = dict
            dict[option.key] = option.value
            return dict
        }
        
        query[kSecClass] = type.key
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            print("Don't save to keychain access query \(query)")
            return
        }
    }
    
    func getDictionary(type: SGKeychainType, options: [SGKeychainOption]) -> NSDictionary {
        guard let result = self.getResult(type: type, options: options), let dictionary = result as? NSDictionary else {
            return [:]
        }
        
        return dictionary
    }
    
    func getString(type: SGKeychainType, options: [SGKeychainOption]) -> String? {
        guard let data = self.getData(type: type, options: options) else {
            print("Keychain not found data")
            return nil
        }
        guard let string = String(data: data, encoding: .utf8) else {
            print("Internal error")
            return nil
        }
        return string
    }
    
    func getData(type: SGKeychainType, options: [SGKeychainOption]) -> Data? {
        let result = self.getResult(type: type, options: options)
        return result as? Data
    }
    
    func delete(type: SGKeychainType, options: [SGKeychainOption]) {
        var query = options.reduce([CFString: Any]()) { dict, option in
            var dict = dict
            dict[option.key] = option.value
            return dict
        }
        
        query[kSecClass] = type.key
        
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess {
            print("Don't delete from keychain access by query \(query)")
        }
    }
    
    func update(type: SGKeychainType, options: [SGKeychainOption], updateOptions: [SGKeychainOption]) {
        var query = options.reduce([CFString: Any]()) { dict, option in
            var dict = dict
            dict[option.key] = option.value
            return dict
        }
        
        query[kSecClass] = type.key
        
        let updateQuery = updateOptions.reduce([CFString: Any]()) { dict, option in
            var dict = dict
            dict[option.key] = option.value
            return dict
        }
        
        let status = SecItemUpdate(query as CFDictionary, updateQuery as CFDictionary)
        if status != errSecSuccess {
            print("Don't update in keychain access for query \(query), updateQuery \(query)")
        }
    }
    
    // - Private Methods
    private func getResult(type: SGKeychainType, options: [SGKeychainOption]) -> AnyObject? {
        var query = options.reduce([CFString: Any]()) { dict, option in
            var dict = dict
            dict[option.key] = option.value
            return dict
        }
        
        query[kSecClass] = type.key
        query[kSecReturnData] = kCFBooleanTrue
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            print("SGKeychain don't find value for query \(query)")
            return nil
        }
        
        return result
    }
}
