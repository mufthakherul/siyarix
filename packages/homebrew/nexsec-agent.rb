class NexsecAgent < Formula
  include Language::Python::Virtualenv

  desc "NexSec AI-powered local security automation CLI"
  homepage "https://github.com/mufthakherul/NexSec"
  url "https://github.com/mufthakherul/NexSec/archive/refs/tags/cli-agent-v0.3.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_SHA256"
  license "MIT"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "NexSec Agent", shell_output("#{bin}/nexsec-agent --version")
  end
end
