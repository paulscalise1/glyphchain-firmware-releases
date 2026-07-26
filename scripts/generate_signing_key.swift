#!/usr/bin/env swift

import CryptoKit
import Foundation
import Security

let service = "com.glyphchain.firmware-signing"
let defaultKeyID = "glyphchain-release-2026-01"

guard (2...3).contains(CommandLine.arguments.count) else {
    FileHandle.standardError.write(
        Data("usage: generate_signing_key.swift PUBLIC_KEY_OUTPUT [KEY_ID]\n".utf8)
    )
    exit(2)
}

let publicKeyURL = URL(fileURLWithPath: CommandLine.arguments[1])
let keyID = CommandLine.arguments.count == 3 ? CommandLine.arguments[2] : defaultKeyID

do {
    try ensureKeyDoesNotExist(service: service, keyID: keyID)

    let privateKey = Curve25519.Signing.PrivateKey()
    var keychainAccess: SecAccess?
    let accessStatus = SecAccessCreate(
        "Glyphchain Firmware Signing Key" as CFString,
        [] as CFArray,
        &keychainAccess
    )
    guard accessStatus == errSecSuccess, let keychainAccess else {
        throw SigningKeyError.keychain(accessStatus)
    }

    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keyID,
        kSecAttrLabel as String: "Glyphchain Firmware Signing Key",
        kSecAttrDescription as String: "Ed25519 private key for signed Glyphchain firmware manifests",
        kSecAttrAccess as String: keychainAccess,
        kSecValueData as String: privateKey.rawRepresentation,
    ]

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
        throw SigningKeyError.keychain(addStatus)
    }

    try FileManager.default.createDirectory(
        at: publicKeyURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let encodedPublicKey = privateKey.publicKey.rawRepresentation.base64EncodedString() + "\n"
    try encodedPublicKey.write(to: publicKeyURL, atomically: true, encoding: .utf8)

    print("Created Glyphchain firmware signing key.")
    print("Keychain service: \(service)")
    print("Key ID: \(keyID)")
    print("Public key: \(publicKeyURL.path)")
    print("The private key was not written to disk.")
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    exit(1)
}

func ensureKeyDoesNotExist(service: String, keyID: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keyID,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    let status = SecItemCopyMatching(query as CFDictionary, nil)
    switch status {
    case errSecItemNotFound:
        return
    case errSecSuccess:
        throw SigningKeyError.alreadyExists(keyID)
    default:
        throw SigningKeyError.keychain(status)
    }
}

enum SigningKeyError: LocalizedError {
    case alreadyExists(String)
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .alreadyExists(let keyID):
            return "A Keychain signing key already exists for \(keyID); it was not replaced."
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"
            return "Keychain error \(status): \(message)"
        }
    }
}
