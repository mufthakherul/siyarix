# Siyarix Security Agent (NPM Package)

<div align="center">
  <p><strong>A humble, open-source security agent by Mufthakherul. Built for learning, research, and community collaboration.</strong></p>
</div>

---

**Siyarix** is a command-line security agent that explores how we can combine autonomous AI planning with classic security tools right in the terminal.

*(Note: The core of Siyarix is written in Python. This NPM package is provided as a wrapper/utility for Node.js developers who wish to integrate or trigger Siyarix within their JavaScript/TypeScript ecosystems.)*

### 🌱 Our Story
Siyarix started out as a college project to experiment with AI and security automation. As the codebase grew and became surprisingly useful, we decided to open-source it! Today, it's maintained by the Mufthakherul community. We don't claim to be an "ultra-premium enterprise solution"—rather, Siyarix is a practical, lightweight, and modern tool meant for students, researchers, penetration testers, and anyone curious about AI-driven security.

## 🚀 Quick Start

To install Siyarix globally via npm:

```bash
npm install -g @mufthakherul/siyarix
```

*(Ensure you have Python 3.11+ installed on your system as it is required under the hood).*

### Basic Usage

```bash
# Launch the interactive chat assistant
siyarix

# Tell the agent what to do using natural language
siyarix run "scan example.com with nmap and nuclei, then summarize the results"
```

## 🤝 Contributing & Documentation

We absolutely love contributions! Since Siyarix is a community project, we welcome everyone—especially beginners and students looking for their first open-source project.

For full documentation, architecture details, and contribution guidelines, please visit our [main GitHub repository](https://github.com/Mufthakherul/siyarix).

## 📜 License

Siyarix is released under the MIT License. Please use it responsibly and only on systems you have permission to test!
