class Siyarix < Formula
  include Language::Python::Virtualenv

  desc "Siyarix — AI Cybersecurity Orchestration Agent"
  homepage "https://github.com/mufthakherul/siyarix"
  url "https://github.com/mufthakherul/siyarix/archive/refs/tags/v1.0.1.tar.gz"
  license "AGPL-3.0-or-later"

  depends_on "python@3.12"

  livecheck do
    url :stable
    strategy :github_latest
  end

  def install
    virtualenv_install_with_resources :using => "python@3.12"
  end

  def caveats
    <<~EOS
      Siyarix requires API keys for AI providers. Configure via:
        siyarix auth set openai --key YOUR_KEY
      or set the OPENAI_API_KEY environment variable.
    EOS
  end

  test do
    assert_match "siyarix", shell_output("#{bin}/siyarix --version")
  end
end
