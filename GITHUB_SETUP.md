# GitHub Setup Guide

## Quick Start (3 Steps)

### Step 1: Create a GitHub Repository

1. Go to [GitHub](https://github.com)
2. Click the **"+"** icon (top right) → **"New repository"**
3. Fill in the details:
   - **Repository name**: `oauth-platform` (or your preferred name)
   - **Description**: "Production-grade OAuth 2.1 + OIDC Authorization & Identity Platform"
   - **Visibility**: Choose **Private** (recommended for security infrastructure)
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
4. Click **"Create repository"**

### Step 2: Connect Your Local Code to GitHub

After creating the repository, GitHub will show you commands. Use these commands in your terminal:

```bash
cd /home/vikram/Projects/outhApp

# Add GitHub as remote (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/oauth-platform.git

# Push your code to GitHub
git push -u origin main
```

**Example** (if your GitHub username is `vikram123`):
```bash
git remote add origin https://github.com/vikram123/oauth-platform.git
git push -u origin main
```

### Step 3: Authenticate

When you run `git push`, you'll be prompted for credentials:

**Option A: Personal Access Token (Recommended)**
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a name: "OAuth Platform"
4. Select scopes: `repo` (full control of private repositories)
5. Click "Generate token"
6. **Copy the token** (you won't see it again!)
7. When pushing, use the token as your password

**Option B: GitHub CLI (Easiest)**
```bash
# Install GitHub CLI (if not installed)
sudo apt install gh

# Authenticate
gh auth login

# Then push
git push -u origin main
```

---

## ✅ What's Already Done

- ✅ Git repository initialized
- ✅ Initial commit created (20 files, 10,981 lines)
- ✅ Branch renamed to `main`
- ✅ `.env` files excluded from version control
- ✅ Secrets protected by `.gitignore`

---

## 🔒 Security Reminder

**NEVER commit these files** (already in `.gitignore`):
- `backend/.env` - Contains database passwords
- `frontend/.env` - Contains API configuration
- `*.pem`, `*.key` - Private keys (Phase 4+)
- `node_modules/` - Dependencies

The `.gitignore` file is already configured to protect all secrets!

---

## 📋 Commands Reference

### Check Git Status
```bash
cd /home/vikram/Projects/outhApp
git status
```

### View Commit History
```bash
git log --oneline
```

### Push Future Changes
```bash
git add .
git commit -m "Your commit message"
git push
```

### Create a New Branch (for Phase 1)
```bash
git checkout -b phase-1-identity-core
# Make changes
git add .
git commit -m "feat: Phase 1 - Identity Core implementation"
git push -u origin phase-1-identity-core
```

---

## 🌟 Recommended GitHub Settings

After pushing to GitHub:

1. **Branch Protection Rules** (Settings → Branches):
   - Require pull request reviews
   - Require status checks to pass
   - Prevent force pushes

2. **Security & Analysis** (Settings → Security):
   - Enable Dependabot alerts
   - Enable secret scanning

3. **About Section** (Main repo page):
   - Add description: "Production-grade OAuth 2.1 + OIDC Authorization & Identity Platform"
   - Add topics: `oauth2`, `oidc`, `openid-connect`, `authorization-server`, `typescript`, `nodejs`, `nextjs`

---

## 🎯 Next Steps

1. Create the GitHub repository
2. Run the `git remote add origin` command (with your repository URL)
3. Run `git push -u origin main`
4. Your code will be on GitHub! 🚀
