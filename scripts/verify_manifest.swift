#!/usr/bin/env swift

import CryptoKit
import Foundation

guard CommandLine.arguments.count == 4 else {
    FileHandle.standardError.write(
        Data("usage: verify_manifest.swift MANIFEST SIGNATURE PUBLIC_KEY\n".utf8)
    )
    exit(2)
}

let manifestURL = URL(fileURLWithPath: CommandLine.arguments[1])
let signatureURL = URL(fileURLWithPath: CommandLine.arguments[2])
let publicKeyURL = URL(fileURLWithPath: CommandLine.arguments[3])

do {
    let manifest = try Data(contentsOf: manifestURL)
    let signature = try Data(contentsOf: signatureURL)
    let encodedPublicKey = try String(contentsOf: publicKeyURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)

    guard let rawPublicKey = Data(base64Encoded: encodedPublicKey) else {
        throw VerificationError.invalidPublicKeyEncoding
    }

    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey)
    guard publicKey.isValidSignature(signature, for: manifest) else {
        throw VerificationError.invalidSignature
    }

    print("Signature valid: \(manifestURL.lastPathComponent)")
} catch {
    FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
    exit(1)
}

enum VerificationError: LocalizedError {
    case invalidPublicKeyEncoding
    case invalidSignature

    var errorDescription: String? {
        switch self {
        case .invalidPublicKeyEncoding:
            return "The public-key file is not valid Base64."
        case .invalidSignature:
            return "The manifest signature is invalid."
        }
    }
}

