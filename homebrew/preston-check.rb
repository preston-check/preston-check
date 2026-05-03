# Homebrew formula for Preston-Check
#
# Tap setup (one-time):
#   brew tap preston-check/preston-check https://github.com/preston-check/homebrew-tap
#
# Install:
#   brew install preston-check
#
# This formula is published to the preston-check/homebrew-tap repository.
# The version, URL, and SHA256 are updated by the release pipeline on each
# tagged release.

class PrestonCheck < Formula
  desc "Pre-deployment security audit for fintech and financial systems"
  homepage "https://preston-check.com"
  url "https://github.com/preston-check/preston-check/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_SHA256_OF_RELEASE_TARBALL"
  license "Apache-2.0"
  version "1.0.0"

  depends_on "bash"
  depends_on "openssl@3"
  depends_on "gawk"
  depends_on "grep"
  depends_on "coreutils"

  def install
    libexec.install Dir["*"]
    (bin/"preston-check").write <<~SH
      #!/bin/bash
      exec "#{libexec}/preston-check.sh" "$@"
    SH
    (bin/"preston-check-issue-license").write <<~SH
      #!/bin/bash
      exec "#{libexec}/tools/issue-license.sh" "$@"
    SH
    (bin/"preston-check-setup-key").write <<~SH
      #!/bin/bash
      exec "#{libexec}/tools/setup-signing-key.sh" "$@"
    SH
    chmod 0755, bin/"preston-check"
    chmod 0755, bin/"preston-check-issue-license"
    chmod 0755, bin/"preston-check-setup-key"
  end

  def caveats
    <<~EOS
      Preston-Check is installed. Free tier runs without any setup.

      To run a scan in the current directory:
        preston-check

      To run with a specific config:
        preston-check --config /path/to/myapp.yml

      For Pro/Enterprise tier, install your license at:
        ~/.preston-check/license

      Documentation: https://preston-check.com
      Community contributions: https://github.com/preston-check/preston-check
    EOS
  end

  test do
    assert_match "PRESTON-CHECK", shell_output("#{bin}/preston-check --help")
  end
end
