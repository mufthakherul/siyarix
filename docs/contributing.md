# Contributing to Phalanx

First off, thank you for considering contributing to Phalanx! 

This project started as a college experiment to see if AI could orchestrate command-line security tools. As the project grew, we decided to open-source it so that others could learn from it. We are incredibly grateful for anyone who wants to help make it better. 

Whether you're a seasoned Python developer, a student looking for their first open-source pull request, or a security researcher with cool ideas, you are explicitly welcome here.

---

## 🤝 How to Get Involved

You don't need to be an expert in AI or Python to contribute! Here are a few ways you can help the project:

1. **Report Bugs**: If something breaks (and let's be honest, it probably will at some point), open an issue on GitHub. Even better if you can include the steps you took to reproduce it!
2. **Suggest Features**: Have an idea for a new tool integration, a cooler UI theme, or a better way to parse outputs? Let us know.
3. **Write Documentation**: Docs are often the hardest part of open source. If you see typos, confusing explanations, or things that could be phrased better, PRs are highly appreciated.
4. **Write Code**: Look for issues tagged `good first issue` if you want a gentle introduction to the codebase. We try to keep these scoped small so you can get a quick win.

---

## 🛠️ The Pull Request Process

We try to keep our PR process as low-stress as possible.

1. **Fork the Repository**: Create your own copy of the Phalanx repository on GitHub and create a new branch for your feature (e.g., `git checkout -b feat/add-new-parser`).
2. **Test Locally**: Make sure the existing tests pass before you push. If you're adding something new, try to add a small test for it in the `tests/` folder! (See [development.md](development.md) for how to run tests locally).
3. **Commit Messages**: Try to be clear about what you changed. We like the conventional commit format (e.g., `feat: added ffuf parser` or `fix: crash on windows shell`), but we won't reject your PR if you forget.
4. **Open the PR**: Submit it against the `main` branch. A maintainer will review it, give you some friendly feedback, and get it merged!

*Note: If you add or change a CLI command, please try to update `docs/cli-reference.md` so other users know about it!*

---

## 🫂 Code of Conduct

We are building a community for learning and research. We expect everyone to be kind, respectful, and encouraging to one another. There is no such thing as a "stupid" question here.

If you find a severe security vulnerability in Phalanx itself, please do not open a public GitHub issue. Instead, please check out [security.md](security.md) for how to report it privately so we can patch it safely. 

Happy hacking, and thank you again for your interest in Phalanx!
