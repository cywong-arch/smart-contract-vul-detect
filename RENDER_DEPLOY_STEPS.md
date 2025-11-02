# 🚀 Step-by-Step Render Deployment Guide

## Part 1: Configure Git (One-time setup)

### Step 1.1: Set Git Identity
Open PowerShell/Command Prompt in your project folder and run:

```powershell
git config --global user.email "your-email@example.com"
git config --global user.name "Your Name"
```

**Replace:**
- `your-email@example.com` with your actual email (can be your GitHub email)
- `Your Name` with your name

**Example:**
```powershell
git config --global user.email "wongc@example.com"
git config --global user.name "Wong C"
```

---

## Part 2: Create GitHub Repository

### Step 2.1: Create Repository on GitHub
1. Go to: **https://github.com**
2. Sign in (or create account if needed)
3. Click the **"+"** icon (top right) → **"New repository"**
4. Fill in:
   - **Repository name**: `smart-contract-vul-detect` (or any name)
   - **Description**: "Smart Contract Vulnerability Detection System"
   - **Visibility**: Public or Private (your choice)
   - **DO NOT** check "Initialize with README" (we already have files)
5. Click **"Create repository"**

### Step 2.2: Copy Repository URL
After creating, GitHub will show you commands. **Copy the HTTPS URL** - it looks like:
```
https://github.com/YOUR_USERNAME/smart-contract-vul-detect.git
```

---

## Part 3: Push Code to GitHub

### Step 3.1: Complete Git Commit
Run these commands in your project folder:

```powershell
cd "FYP Smart Contract Vul Detect"

# Commit your code (if not done already)
git commit -m "Initial commit - Ready for Render deployment"
```

### Step 3.2: Connect to GitHub and Push
```powershell
# Set main branch
git branch -M main

# Add GitHub repository (replace URL with yours)
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git

# Push code to GitHub
git push -u origin main
```

**When prompted:**
- Username: Your GitHub username
- Password: Use a **Personal Access Token** (see below if you need to create one)

---

## Part 4: Create GitHub Personal Access Token (If Needed)

If Git asks for a password, you need a Personal Access Token:

1. Go to: **https://github.com/settings/tokens**
2. Click **"Generate new token"** → **"Generate new token (classic)"**
3. Fill in:
   - **Note**: "Render Deployment"
   - **Expiration**: 90 days (or your choice)
   - **Select scopes**: Check **"repo"** (full control of private repositories)
4. Click **"Generate token"**
5. **Copy the token** (you'll only see it once!)
6. Use this token as your password when pushing

---

## Part 5: Deploy on Render

### Step 5.1: Sign Up for Render
1. Go to: **https://render.com**
2. Click **"Get Started for Free"**
3. Sign up with your **GitHub account** (easiest way)

### Step 5.2: Create New Web Service
1. Once logged in, click **"New +"** button (top right)
2. Select **"Web Service"**

### Step 5.3: Connect Repository
1. Click **"Connect account"** if not connected to GitHub
2. Authorize Render to access your repositories
3. Find and select your repository: `smart-contract-vul-detect` (or your repo name)
4. Click **"Connect"**

### Step 5.4: Configure Service
Fill in these settings:

- **Name**: `smart-contract-detector` (or any name - this becomes your URL)
- **Region**: Choose closest to you (e.g., Singapore, US, Europe)
- **Branch**: `main` (should be auto-selected)
- **Root Directory**: Leave empty (or put `.` if needed)
- **Environment**: `Python 3`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python web_app.py`
- **Instance Type**: `Free` (for testing) or `Starter` ($7/month for always-on)

### Step 5.5: Deploy!
1. Scroll down and click **"Create Web Service"**
2. Render will start building and deploying your app
3. **Wait 5-10 minutes** for the first deployment
4. You'll see build logs in real-time

---

## Part 6: Access Your Deployed App

### Step 6.1: Get Your URL
Once deployment completes, you'll see:
- ✅ **"Your service is live at"**: `https://smart-contract-detector.onrender.com`
- Click the URL to open your app!

### Step 6.2: Test Your App
1. Visit your deployed URL
2. Upload a test contract (or use quick select)
3. Run analysis
4. Verify it works!

---

## 🎯 Quick Command Summary

```powershell
# 1. Configure Git (one-time)
git config --global user.email "your-email@example.com"
git config --global user.name "Your Name"

# 2. In your project folder
cd "FYP Smart Contract Vul Detect"
git commit -m "Initial commit - Ready for Render deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main

# Then go to Render.com and deploy!
```

---

## ✅ Deployment Checklist

- [ ] Git configured with name and email
- [ ] GitHub repository created
- [ ] Code committed locally
- [ ] Code pushed to GitHub
- [ ] Render account created
- [ ] Web service created on Render
- [ ] Repository connected
- [ ] Build and start commands configured
- [ ] Deployment completed
- [ ] App tested and working

---

## 🐛 Troubleshooting

### Issue: "Permission denied" when pushing
**Solution**: Use Personal Access Token instead of password

### Issue: Build fails on Render
**Solution**: Check build logs - usually missing dependency in requirements.txt

### Issue: "Module not found" error
**Solution**: Make sure Flask and all dependencies are in requirements.txt

### Issue: App shows "Application error"
**Solution**: 
1. Check Render logs
2. Verify Start Command is: `python web_app.py`
3. Check that PORT environment variable is set (auto-set by Render)

### Issue: App spins down (free tier)
**Solution**: 
- Free tier spins down after 15 minutes of inactivity
- First request after spin-down takes ~30 seconds
- Upgrade to paid plan for always-on ($7/month)

---

## 📞 Need Help?

- **Render Docs**: https://render.com/docs
- **GitHub Help**: https://docs.github.com
- **Build Logs**: Check in Render dashboard

---

**Good luck with your deployment! 🚀**

