---
name: wander-github-pull
description: Commit and push updated easm-platform code to GitHub (origin/main) with a pre-push safety guard that blocks sensitive files (data/, config.json, dist/, databases, cert private keys, binaries), auto-generates Conventional Commits messages from the staged diff, and runs git pull --rebase before pushing. Also supports pulling/syncing remote updates. Use when the user asks to commit, push, sync, submit, or 提交/推送 updated code to GitHub for this project.
---

# wander-github-pull

把本项目更新后的代码安全地提交并推送到 GitHub（`origin` / `main`），推送前强制安全护栏，提交信息按 Conventional Commits 自动生成。也支持仅拉取/同步远端。

## 适用场景

用户要求「提交代码 / 推送 / push / 同步到 GitHub / 提交更新的代码 / pull 最新代码」时使用。

## 前提

- 在**仓库根目录**执行（用 `git rev-parse --show-toplevel` 确认；不要硬编码绝对路径）。
- remote 为 `origin`，主分支为 `main`（若不同，以 `git remote -v` / `git branch --show-current` 实际值为准）。
- 首次使用先确认 `.gitignore` 已排除 `data/`、`config.json`、`dist/`、`*.db`、`*.key` 等敏感项。

## 提交并推送工作流（默认）

复制此清单并逐步跟踪：

```
- [ ] 1. 定位仓库根 + 查看变更
- [ ] 2. 暂存变更 git add -A
- [ ] 3. 运行安全护栏 guard.sh（命中则中止）
- [ ] 4. 依据 staged diff 生成 Conventional Commits 信息并向用户确认
- [ ] 5. git commit
- [ ] 6. git pull --rebase origin main（冲突则停下报告）
- [ ] 7. git push origin main
- [ ] 8. 推送后复核
```

**步骤 1 — 定位与查看**
```bash
cd "$(git rev-parse --show-toplevel)"
git branch --show-current && git status --short
```

**步骤 2 — 暂存**
```bash
git add -A
```

**步骤 3 — 安全护栏（强制）**
```bash
bash .qoder/skills/wander-github-pull/scripts/guard.sh
```
- 退出码 `0`：干净，继续。
- 退出码 `1`：**立即中止**，把脚本列出的敏感文件报告给用户，按脚本提示用 `git rm --cached <文件>` 移除并修正 `.gitignore` 后重来。绝不在护栏失败时提交或推送。

**步骤 4 — 生成提交信息**
读取 `git diff --cached --stat` 与（必要时）`git diff --cached` 归纳变更，按下方规范生成信息，**提交前把拟用的信息展示给用户确认**。

**步骤 5 — 提交**
```bash
git commit -m "<type>(<scope>): <subject>"
```
> 若本机未配置提交身份，用单次覆盖而不改全局配置：
> `git -c user.name="<名字>" -c user.email="<邮箱>" commit -m "..."`

**步骤 6 — 同步远端（push 前先 pull --rebase）**
```bash
git pull --rebase origin main
```
- 出现冲突：**停下**，用 `git status` 展示冲突文件让用户解决；解决后 `git rebase --continue`，或 `git rebase --abort` 回退。不要在冲突未解决时推送。

**步骤 7 — 推送**
```bash
git push origin main
# 若为分支首次推送：git push -u origin main
```

**步骤 8 — 复核**
```bash
git log --oneline -1
git ls-files | grep -E '(^|/)data/|(^|/)config\.json$|(^|/)dist/|\.db$|\.key$' && echo "!!! 有敏感文件被跟踪" || echo "远端跟踪列表干净"
```

## 提交信息规范（Conventional Commits）

格式：`<type>(<scope>): <subject>`，subject 用祈使句、不加句号。

| type | 用途 |
|------|------|
| feat | 新功能 |
| fix | 缺陷修复 |
| chore | 构建/杂项/依赖/仓库维护 |
| docs | 文档 |
| refactor | 重构（无功能变化） |
| test | 测试 |
| style | 格式（不影响逻辑） |

scope 取模块名，如 `scanner` / `web` / `store` / `notify` / `ui`。

**示例**
```
feat(scanner): 支持自定义端口范围扫描
fix(web): 批量删除空选择时透传后端错误文案
chore(repo): 补充 .gitignore 排除 data/ 与 config.json
docs: 新增架构升级评估文档
```
一次提交涉及多类时，用主要变更定 type，body 里分点说明。

## 仅拉取 / 同步模式

用户只要「拉取最新代码」时：
```bash
cd "$(git rev-parse --show-toplevel)"
git status --short            # 有未提交变更先提示用户提交或 stash
git pull --rebase origin main
```
有本地未提交改动时，先 `git stash` 再 pull，之后 `git stash pop`；或建议先走上面的提交工作流。

## 故障排查

- **`Permission denied (publickey)`**：SSH 公钥未注册到 GitHub 或 ssh-agent 未加载。
  - 查看公钥并添加到 GitHub（Settings → SSH and GPG keys）：`cat ~/.ssh/id_ed25519.pub`
  - 加载并测试：`ssh-add ~/.ssh/id_ed25519 && ssh -T git@github.com`
  - 或改用 HTTPS + 个人访问令牌（PAT）：`git remote set-url origin https://github.com/<用户>/<仓库>.git` 后 `git push`，密码处粘贴 PAT（非账号密码）。
- **push 被拒（non-fast-forward）**：远端有新提交，先 `git pull --rebase origin main` 再 push。
- **rebase 冲突**：解决冲突文件后 `git add <文件> && git rebase --continue`；放弃用 `git rebase --abort`。
- **护栏误报**：确认命中的确是敏感文件；若是被误匹配的正常文件，调整 `.gitignore` 与 `guard.sh` 的 `PATTERN` 保持一致。
- **凭据边界**：不代持/不写入用户的 SSH 私钥、PAT 或账号密码；此类认证由用户在自己环境完成。
