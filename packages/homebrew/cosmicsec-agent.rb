class CosmicsecAgent < Formula
  include Language::Python::Virtualenv

  desc "CosmicSec AI-powered local security automation CLI"
  homepage "https://github.com/mufthakherul/CosmicSec"
  url "https://github.com/mufthakherul/CosmicSec/archive/refs/tags/cli-agent-v0.3.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_SHA256"
  license "MIT"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "CosmicSec Agent", shell_output("#{bin}/cosmicsec-agent --version")
  end
end
