# 🔌 The Siyarix Plugin Exception

Siyarix is licensed under the **AGPL-3.0-or-later** license to ensure the core project remains open. However, I also want to encourage developers to build useful third-party plugins. 

To make this possible, I've added a special **Plugin Exception** to the AGPL-3.0 terms.

> [!NOTE]
> **TL;DR:** Siyarix core must remain open-source (AGPL), but you can write plugins for Siyarix using *any* license you want—including closed-source ones!

## 📜 The Official Exception Text

As a special exception to the GNU Affero General Public License version 3 or later (the "AGPL"), the copyright holders of Siyarix give you permission to convey a work that contains **unmodified Siyarix code** combined with **plugins** under terms of your choice, provided that you meet the following conditions:

### 1. What Defines a "Plugin"?

A "Plugin" is strictly defined as any file, script, or module that:
- Is loaded dynamically via the official Siyarix plugin loader (typically from `~/.siyarix/plugins/`).
- Does **not** contain, modify, or overwrite any original Siyarix source code.
- Communicates with Siyarix exclusively through documented, public APIs.

### 2. The Conditions

If you distribute a combined work (Siyarix + Your Plugin), you must adhere to these rules:
- **The Core Stays Open:** Siyarix itself must remain under AGPL-3.0-or-later. 
- **Your Plugin is Yours:** Your plugins may be licensed under *any* terms.
- **No False Endorsement:** You must not misrepresent the origin of Siyarix or imply an official endorsement.
- **Include This Notice:** You must include a copy of this exact exception notice.

### 3. Practical Scenarios

| Scenario | Is it Permitted? |
|----------|-----------|
| 🏢 Write a closed-source plugin for your own team. | **✅ Yes** |
| 🌍 Distribute an open-source plugin under MIT. | **✅ Yes** |
| ❌ Modify the core engine in `src/siyarix/` and keep the code secret. | **❌ No** *(Core changes must be AGPL)* |
| 📦 Bundle a modified open-source Siyarix core with a closed-source plugin. | **✅ Yes** *(As long as you publish the core modifications)* |
