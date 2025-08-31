# Contributing to Kosh

Thank you for considering contributing to **Kosh**!  
We’re excited to have you on board. Whether it’s fixing a bug, improving documentation, or adding a new feature, all contributions are welcome.

---

## 📌 How to Contribute

### 1. Fork the Repository
- Click on the **Fork** button in the top-right corner of this repository.
- Clone your fork locally:
  ```bash
  git clone https://github.com/<your-username>/kosh.git

* Navigate into the project folder:

  ```bash
  cd kosh
  ```

### 2. Set Upstream Remote (Recommended)

```bash
git remote add upstream https://github.com/kavish-s/kosh.git
```

To keep your fork updated:

```bash
git fetch upstream
git merge upstream/main
```

### 3. Create a Feature Branch

Always create a new branch before making changes:

```bash
git checkout -b feature/<short-description>
```

**Examples:**

* `feature/aes-enhancement`
* `fix/file-download-bug`
* `docs/update-readme`

---

## 🛠️ Development Guidelines

### Code Style

* **Language**: Python (Flask backend), JavaScript, HTML, Tailwind CSS.
* Follow **PEP8** for Python code.
* Use **Bootstrap/Tailwind** classes for UI styling instead of inline CSS.
* Keep code modular and reusable.
* Avoid committing secrets, API keys, or passwords.

---

## 💬 Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>
```

**Allowed types:**

* `feat` → New feature
* `fix` → Bug fix
* `docs` → Documentation changes
* `refactor` → Code restructuring without changing functionality
* `style` → Formatting changes, no code logic updates
* `test` → Adding or updating tests

**Examples:**

* `feat: add AES-256 encryption for file uploads`
* `fix: resolve broken file download route`
* `docs: update README with project setup steps`

---

## ✅ Pull Request Process

1. Make sure your code is **tested** and **linted**.
2. Update the documentation if required.
3. Push your branch:

   ```bash
   git push origin feature/<branch-name>
   ```
4. Open a **Pull Request (PR)**:

   * Provide a clear title and description.
   * Link related issues if applicable.
5. Wait for code review and address feedback.

---

## 🐛 Reporting Issues

If you find a bug or have a feature request:

1. Check if it’s already reported under [Issues](../../issues).
2. If not, create a new issue with:

   * Clear title and description.
   * Steps to reproduce (if applicable).
   * Expected vs actual behavior.
   * Screenshots or logs if relevant.

---

## 📜 Code of Conduct

By contributing, you agree to maintain a respectful and inclusive environment for everyone.
Be kind, constructive, and collaborative.

---

## 🙌 Acknowledgments

Thanks for taking the time to contribute to **Kosh**.
Together, we’re making LAN-based secure file sharing faster, safer, and smarter.

