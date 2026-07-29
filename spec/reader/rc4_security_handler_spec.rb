# typed: false
# coding: utf-8

require 'digest/md5'

describe PDF::Reader::Rc4 do
  # Well known RC4 test vectors. See:
  # https://en.wikipedia.org/wiki/RC4#Test_vectors
  describe "#decrypt" do
    it "matches the 'Key'/'Plaintext' test vector" do
      rc4 = PDF::Reader::Rc4.new("Key")
      result = rc4.decrypt("Plaintext")
      expect(result.unpack1("H*")).to eq("bbf316e8d940af0ad3")
    end

    it "matches the 'Wiki'/'pedia' test vector" do
      rc4 = PDF::Reader::Rc4.new("Wiki")
      result = rc4.decrypt("pedia")
      expect(result.unpack1("H*")).to eq("1021bf0420")
    end

    it "matches the 'Secret'/'Attack at dawn' test vector" do
      rc4 = PDF::Reader::Rc4.new("Secret")
      result = rc4.decrypt("Attack at dawn")
      expect(result.unpack1("H*")).to eq("45a01f645fc35b383552544b9bf5")
    end

    it "raises ArgumentError instead of ZeroDivisionError for an empty key" do
      expect { PDF::Reader::Rc4.new("") }.to raise_error(ArgumentError, "key must not be empty")
    end

    it "is symmetric - decrypting the ciphertext returns the original plaintext" do
      plaintext = "Plaintext"
      ciphertext = PDF::Reader::Rc4.new("Key").decrypt(plaintext)
      roundtrip  = PDF::Reader::Rc4.new("Key").decrypt(ciphertext)
      expect(roundtrip).to eq(plaintext)
    end

    it "aliases encrypt to the same operation as decrypt" do
      key = "Secret"
      plaintext = "Attack at dawn"
      encrypted = PDF::Reader::Rc4.new(key).encrypt(plaintext)
      decrypted = PDF::Reader::Rc4.new(key).decrypt(plaintext)
      expect(encrypted).to eq(decrypted)
    end
  end
end

describe PDF::Reader::Rc4SecurityHandler do
  let(:key) { "test_encryption_key" }
  let(:handler) { PDF::Reader::Rc4SecurityHandler.new(key) }
  let(:reference) { PDF::Reader::Reference.new(1, 0) }

  describe "#decrypt" do
    it "decrypts data that was encrypted using the PDF spec's object-key algorithm" do
      plaintext = "Hello, World!"
      buf = encrypt_test_data(plaintext, key, reference)

      result = handler.decrypt(buf, reference)
      expect(result).to eq(plaintext)
    end

    it "round trips arbitrary binary data" do
      plaintext = (0..255).to_a.pack("C*")
      buf = encrypt_test_data(plaintext, key, reference)

      result = handler.decrypt(buf, reference)
      expect(result).to eq(plaintext)
    end

    it "returns garbage, not an error, when the key is wrong" do
      wrong_handler = PDF::Reader::Rc4SecurityHandler.new("wrong_key_here!")

      plaintext = "Hello, World!"
      buf = encrypt_test_data(plaintext, key, reference)

      result = wrong_handler.decrypt(buf, reference)
      expect(result).not_to eq(plaintext)
      expect(result).to be_a(String)
    end
  end

  private

  # Helper method to create encrypted test data using the same object-key
  # derivation algorithm the handler itself uses (PDF spec Algorithm 1)
  #
  # @param plaintext [String] the text to encrypt
  # @param encryption_key [String] the encryption key to use
  # @param ref [PDF::Reader::Reference] the PDF reference for key generation
  # @return [String] ciphertext ready for the handler's decrypt method
  def encrypt_test_data(plaintext, encryption_key, ref)
    obj_key = encryption_key.dup
    (0..2).each { |e| obj_key << (ref.id >> e*8 & 0xFF) }
    (0..1).each { |e| obj_key << (ref.gen >> e*8 & 0xFF) }
    length = obj_key.length < 16 ? obj_key.length : 16
    rc4 = PDF::Reader::Rc4.new(Digest::MD5.digest(obj_key)[0, length])
    rc4.encrypt(plaintext)
  end
end
