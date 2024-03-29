# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Vulnapi < Formula
  desc "VulnAPI is an open-source project designed to help you scan your APIs for common security vulnerabilities and weaknesses."
  homepage "https://vulnapi.cerberauth.com/"
  version "0.4.4-beta.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/cerberauth/vulnapi/releases/download/v0.4.4-beta.2/vulnapi_Darwin_x86_64.tar.gz"
      sha256 "da28fef87af369d21de90414e9746aff71dd92fe2e291352e3ac33a8e97e0d9f"

      def install
        bin.install "vulnapi"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/cerberauth/vulnapi/releases/download/v0.4.4-beta.2/vulnapi_Darwin_arm64.tar.gz"
      sha256 "4152e7d9b6f71842f871c2515d163dfb889fb929dabc5c18e229ef0809cb704d"

      def install
        bin.install "vulnapi"
      end
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/cerberauth/vulnapi/releases/download/v0.4.4-beta.2/vulnapi_Linux_x86_64.tar.gz"
      sha256 "5cf7d9dee1f19e976d91336cdc953f8c619222ba70e9bfd9c4e86bdefb7ebf72"

      def install
        bin.install "vulnapi"
      end
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/cerberauth/vulnapi/releases/download/v0.4.4-beta.2/vulnapi_Linux_arm64.tar.gz"
      sha256 "c3fdaf6c33971915182781d25291289940f199f85b5df760a2d5a13c8add3733"

      def install
        bin.install "vulnapi"
      end
    end
  end
end
