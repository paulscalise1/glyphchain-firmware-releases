#!/usr/bin/env swift

import CryptoKit
import Foundation
import Security

let service = "com.glyphchain.firmware-signing"
let defaultKeyID = "glyphchain-release-2026-01"

guard (3...4).contains(CommandLine.arguments.count) else {
    FileHandle.standardError.write(
        Data("usage: sign_manifest.swift MANIFEST OUTPUT_SIGNATURE [KEY_ID]\n".utf8)
    )
    exit(2)
}

let manifestURL = URL(fileURLWithPath: CommandLine.arguments[1])
let signatureURL = URL(fileURLWithPath: CommandLine.arguments[2])
let keyID = CommandLine.arguments.count == 4 ? CommandLine.arguments[3] : defaultKeyID

do {
    let manifest = try Data(contentsOf: manifestURL)
    let rawKey = try loadPrivateKey(service: service, keyID: keyID)
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawKey)
    let signature = try privateKey.signature(for: manifest)
    try signature.write(to: signatureURL, options: .atomic)

    print("Signed \(manifestURL.lastPathComponent)")
    print("Key ID: \(keyID)")
    print("Signature: \(signatureURL.path)")
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    exit(1)
}

func loadPrivateKey(service: String, keyID: String) throws -> Data {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keyID,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else {
        throw SigningError.keychain(status)
    }
    guard let keyData = item as? Data else {
        throw SigningError.invalidKeychainData
    }
    return keyData
}

enum SigningError: LocalizedError {
    case invalidKeychainData
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidKeychainData:
            return "The Keychain item does not contain a valid private-key value."
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            return "Keychain error \(status): \(message)"
        }
    }
}
