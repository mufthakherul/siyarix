# Frequently Asked Questions

**Q: What exactly is Siyarix?**
A: Siyarix is an open-source, AI-assisted security agent for your terminal. It helps you orchestrate security scans, translate commands across different operating systems, and learn about security concepts interactively. It started as a college project and is now maintained by the Mufthakherul community for educational and research purposes.

**Q: Is it safe to use AI to run security commands?**
A: Safety is our absolute top priority! Siyarix doesn't just blindly run whatever the AI suggests. The execution engine has built-in safety checks (a "Safety Resolver") to block dangerous shell commands (like `rm -rf /` or `mkfs`). However, as with any security tool, you should *always* review the AI's plan and only run scans against networks you own or have explicit permission to test.

**Q: Does Siyarix include security tools like Nmap out of the box?**
A: No, Siyarix acts as a "brain" that orchestrates the tools you already have. You will need to have tools like Nmap, Nuclei, or Ffuf installed on your system independently. When you start Siyarix, its Tool Registry will automatically detect what is available on your `PATH`.

**Q: Which AI models can I use?**
A: We support several major providers! You can use OpenAI, Google Gemini, or Anthropic. If you are privacy-conscious or working in an air-gapped environment, you can also run local models using Ollama!

**Q: I don't like the colors, can I change them?**
A: Absolutely! We built in a full theming engine using the Rich library. Open the interactive shell and type `/theme mode minimal` or `/theme mode neon` to find a style you like. You can preview all of them using `siyarix theme preview`.

**Q: I found a bug, how do I get help?**
A: Check out our [Troubleshooting Guide](troubleshooting.md) first. If you're still stuck, feel free to open an issue on our GitHub repository. We are a friendly community and we're happy to help you figure it out.

**Q: How do I get involved in the project?**
A: We'd love your help! Check out the [Contributing Guide](contributing.md) for how to submit bug reports, feature requests, or your very first pull request.
