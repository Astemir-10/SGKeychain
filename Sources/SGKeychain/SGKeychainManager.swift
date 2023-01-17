//
//  SGKeychainManager.swift
//  
//
//  Created by Astemir Shibzuhov on 1/17/23.
//

import Foundation

public enum SGKeychainManagerBuilder {
    public static func build() -> SGKeychainManager {
        let manager = SGKeychainManager(service: SGKeychainService())
        return manager
    }
}


public final class SGKeychainManager {
    private let service: SGKeychainServiceProtocol
    
    public func saveWithBiometry(key: String, value: String) {
        guard let valueData = value.data(using: .utf8) else {
            return
        }
        self.service.save(type: .genericPassword, options: [
                                                                 .account(key),
                                                            .valueData(valueData),
                                                                 .accessControl(.whenPasscodeSetThisDeviceOnly(.userPresence))])
    }
    
    public func save(key: String, value: String) {
        guard let valueData = value.data(using: .utf8) else {
            return
        }
        self.service.save(type: .genericPassword, options: [
                                                                 .account(key),
                                                            .valueData(valueData)])
    }
    
    public func get(by key: String) -> String? {
        return self.service.getString(type: .genericPassword, options: [.account(key), .matchLimit(.one)])
    }
    
    public func delete(by key: String) {
        self.service.delete(type: .genericPassword, options: [.account(key)])
    }
    
    init(service: SGKeychainServiceProtocol) {
        self.service = service
    }
}
