# ⚡ Quick Deployment Guide

## 🎯 Recommended: Render.com (Free & Easy)

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "Ready for deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to https://render.com
2. Sign up (free with GitHub)
3. Click "New +" → "Web Service"
4. Connect your GitHub repo
5. Configure:
   - **Name**: smart-contract-detector (or any name)
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python web_app.py`
   - **Plan**: Free
6. Click "Create Web Service"
7. Wait 5-10 minutes
8. **Done!** Your app is live at: `https://your-app-name.onrender.com`

---

## 🚂 Alternative: Railway.app

1. Push code to GitHub (same as above)
2. Go to https://railway.app
3. Sign up with GitHub
4. Click "New Project" → "Deploy from GitHub"
5. Select your repository
6. **Done!** Auto-deploys at: `https://your-app-name.up.railway.app`

---

## ✅ Files Already Created for You

- ✅ `Procfile` - For Heroku/Render
- ✅ `runtime.txt` - Python version
- ✅ `render.yaml` - Render configuration
- ✅ `app.json` - Heroku configuration
- ✅ `.gitignore` - Git exclusions
- ✅ `requirements.txt` - Updated with Flask
- ✅ `web_app.py` - Updated for production

---

## 🔍 After Deployment

Test your app:
1. Upload a test contract
2. Select detectors
3. Run analysis
4. Verify results

---

## 📞 Need Help?

Check `DEPLOYMENT.md` for detailed instructions and troubleshooting!

