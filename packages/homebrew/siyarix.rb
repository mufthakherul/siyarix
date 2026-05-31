class Siyarix < Formula
  include Language::Python::Virtualenv

  desc "Siyarix — AI Cybersecurity Orchestration Agent"
  homepage "https://github.com/mufthakherul/siyarix"
  url "https://github.com/mufthakherul/siyarix/archive/refs/tags/v1.0.0-beta.tar.gz"
  sha256 "SKIP_AUTO"  # Auto-populated by `brew audit --strict --online`
  license "AGPL-3.0-or-later"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources :using => "python@3.12"
  end

  test do
    assert_match "siyarix", shell_output("#{bin}/siyarix --version")
  end
end
