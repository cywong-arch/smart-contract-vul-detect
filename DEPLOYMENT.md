# 🚀 Deployment Guide

This guide will help you deploy the Smart Contract Vulnerability Detection System to various cloud platforms.

## 📋 Prerequisites

1. **Git** installed on your computer
2. A **GitHub account** (or GitLab/Bitbucket)
3. Account on your chosen hosting platform

---

## 🌐 Deployment Options

### **Option 1: Render (Recommended - Free Tier Available)** ⭐

**Why Render?**
- ✅ Free tier available (spins down after inactivity)
- ✅ Easy deployment from GitHub
- ✅ Automatic SSL certificates
- ✅ Simple configuration

**Steps:**

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git push -u origin main
   ```

2. **Go to Render:**
   - Visit: https://render.com
   - Sign up/Sign in (can use GitHub account)

3. **Create New Web Service:**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select your repository

4. **Configure Service:**
   - **Name**: smart-contract-vul-detect (or any name)
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python web_app.py`
   - **Instance Type**: Free (or paid)

5. **Deploy:**
   - Click "Create Web Service"
   - Wait for deployment (5-10 minutes)
   - Your app will be available at: `https://your-app-name.onrender.com`

---

### **Option 2: Railway** 🚂

**Why Railway?**
- ✅ Free tier with $5 credit monthly
- ✅ Simple deployment
- ✅ Good for development

**Steps:**

1. **Push code to GitHub** (same as Render steps above)

2. **Go to Railway:**
   - Visit: https://railway.app
   - Sign up with GitHub

3. **Create New Project:**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository

4. **Configure:**
   - Railway auto-detects Python
   - Add environment variable: `PORT` = (auto-set by Railway)
   - Deploy automatically starts

5. **Get URL:**
   - Railway provides a URL: `https://your-app-name.up.railway.app`

---

### **Option 3: Heroku** ☁️

**Note:** Heroku no longer has a free tier. You'll need a paid account ($5/month minimum).

**Steps:**

1. **Install Heroku CLI:**
   - Download from: https://devcenter.heroku.com/articles/heroku-cli

2. **Login to Heroku:**
   ```bash
   heroku login
   ```

3. **Create Heroku App:**
   ```bash
   heroku create your-app-name
   ```

4. **Deploy:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git push heroku main
   ```

5. **Open App:**
   ```bash
   heroku open
   ```

---

### **Option 4: PythonAnywhere** 🐍

**Why PythonAnywhere?**
- ✅ Free tier available
- ✅ Python-focused hosting
- ✅ Simple setup

**Steps:**

1. **Sign up:** https://www.pythonanywhere.com

2. **Upload Files:**
   - Use the Files tab to upload your project
   - Or use Git: `git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git`

3. **Configure Web App:**
   - Go to "Web" tab
   - Click "Add a new web app"
   - Select Python 3.10
   - Choose "Manual configuration"

4. **Edit WSGI file:**
   - In the WSGI configuration file, add:
   ```python
   import sys
   path = '/home/YOUR_USERNAME/YOUR_PROJECT_FOLDER'
   if path not in sys.path:
       sys.path.append(path)
   
   from web_app import app
   
   application = app
   ```

5. **Reload Web App:**
   - Click "Reload" button
   - Access at: `https://YOUR_USERNAME.pythonanywhere.com`

---

### **Option 5: Fly.io** ✈️

**Why Fly.io?**
- ✅ Free tier available
- ✅ Global deployment
- ✅ Good performance

**Steps:**

1. **Install Fly CLI:**
   ```bash
   # Windows: Download from https://fly.io/docs/getting-started/installing-flyctl/
   ```

2. **Create fly.toml:**
   ```bash
   fly launch
   ```

3. **Deploy:**
   ```bash
   fly deploy
   ```

---

## 🔧 Common Configuration Steps

### Environment Variables

Some platforms allow you to set environment variables:

- `PORT`: Usually auto-set by platform
- `FLASK_ENV`: Set to `production` for production

### File Size Limits

Some platforms have file upload limits:
- **Render**: 100MB free tier
- **Railway**: Depends on plan
- **Heroku**: 30MB slug size limit

Your current limit is 16MB (set in web_app.py).

---

## ✅ Verification Checklist

After deployment, verify:

- [ ] App loads without errors
- [ ] Can upload .sol files
- [ ] Test contracts work
- [ ] Analysis completes successfully
- [ ] Results display correctly
- [ ] Download functionality works

---

## 🐛 Troubleshooting

### Issue: "Module not found"
**Solution:** Ensure all dependencies are in `requirements.txt`

### Issue: "Port already in use"
**Solution:** The app uses `os.environ.get('PORT', 5000)` - platforms set this automatically

### Issue: "Application error"
**Solution:** Check platform logs for error messages

### Issue: "File too large"
**Solution:** Current limit is 16MB. You can adjust in `web_app.py`:
```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
```

---

## 📝 Quick Deploy Commands

**Render:**
- Push to GitHub → Connect repo → Deploy

**Railway:**
- Push to GitHub → Connect repo → Auto-deploy

**Heroku:**
```bash
heroku create your-app-name
git push heroku main
```

---

## 🎯 Recommended Platform

**For FYP Project:** **Render** or **Railway**
- Both have free tiers
- Easy GitHub integration
- Automatic deployments
- Good documentation

---

## 📚 Additional Resources

- **Render Docs**: https://render.com/docs
- **Railway Docs**: https://docs.railway.app
- **Heroku Docs**: https://devcenter.heroku.com
- **PythonAnywhere Docs**: https://help.pythonanywhere.com

---

Good luck with your deployment! 🚀

