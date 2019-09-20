Pod::Spec.new do |spec|

  spec.name         = "ItemEncrypt"
  spec.version      = "0.3.1"
  spec.summary      = "A simple Swift API for encrypting arbitrary data and data types."
  spec.description  = <<-DESC
    A simple Swift API for encrypting arbitrary data and data types.
    We built an `Encoder` implementation based upon the open-source Swift `Encoder` types. (Think `JSONEncoder` and `JSONSerialization`.) Any Encodable type can be turned into Data, and encrypted! Quickly and easily derive encryption keys (`EncryptionKey` objects) from user passwords, encrypt or decrypt arbitrary `Codable` types (with `EncryptionEncoder` and `EncryptionDecoder`), or do the same with arbitrary data or streams (using `EncryptionSerialization`). Keys may safely be stored and retrieved in the system Keychain using `KeychainHandle`, but the user is primarily responsible for knowing their password.
                   DESC

  spec.homepage = "https://github.com/SparrowBlaze/ItemEncryptor"
  spec.license = { :type => "MIT", :file => "LICENSE" }
  spec.authors = { "SparrowBlaze" => "silverenderman@gmail.com", "James Robinson" => "jnrobinson016@gmail.com" }

  spec.ios.deployment_target = "11.4"
  spec.osx.deployment_target = "10.13"
  spec.tvos.deployment_target = "11.4"
  spec.watchos.deployment_target = "5.1"
  spec.swift_versions = "5.0"

  spec.source = { :git => "https://github.com/SparrowBlaze/ItemEncryptor.git", :tag => "v#{spec.version}" }
  spec.source_files  = "Sources", "ItemEncrypt/Sources/**/*.swift"
  spec.exclude_files = "ItemEncrypt/Sources/EncryptionEncoder-JSON.swift"

  spec.frameworks  = "Security", "Foundation", "IDZSwiftCommonCrypto"
  spec.requires_arc = true
  spec.dependency "IDZSwiftCommonCrypto", "~> 0.13.0"
end
