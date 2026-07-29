# coding: utf-8
# typed: strict
# frozen_string_literal: true

class PDF::Reader
  # A minimal, self-contained implementation of the RC4 stream cipher, used to decrypt
  # PDFs encrypted with the (legacy, but still spec-compliant) RC4 security handler.
  # Vendored directly to avoid depending on the abandoned ruby-rc4 gem (last released
  # 2012, archived since 2020, and missing license metadata in its gemspec).
  class Rc4 #:nodoc:
    #: (String) -> void
    def initialize(key)
      raise ArgumentError, "key must not be empty" if key.empty?

      @key = key.bytes
      @s = (0..255).to_a
      j = 0
      256.times do |i|
        j = (j + @s[i] + @key[i % @key.length]) & 0xFF
        @s[i], @s[j] = @s[j], @s[i]
      end
      @i = 0
      @j = 0
    end

    # RC4 encryption and decryption are the same operation (XOR with the keystream).
    #: (String) -> String
    def decrypt(data)
      out = String.new(encoding: ::Encoding::ASCII_8BIT)
      data = data.dup.force_encoding(::Encoding::ASCII_8BIT)
      data.each_byte do |byte|
        @i = (@i + 1) & 0xFF
        @j = (@j + @s[@i]) & 0xFF
        @s[@i], @s[@j] = @s[@j], @s[@i]
        k = @s[(@s[@i] + @s[@j]) & 0xFF]
        out << (byte ^ k)
      end
      out
    end

    alias_method :encrypt, :decrypt
  end
end
