## GitHub OAuth Setup Guide for CascadeGuard

### Step 1: Configure GitHub OAuth App Callback URL

The 404 error you're seeing means the **Authorization callback URL** in your GitHub OAuth app isn't configured correctly.

Go here: **https://github.com/settings/developers**

1. Click on your OAuth app
2. Look for **Authorization callback URL**
3. Set it to exactly this:

```
http://localhost:8501
```

⚠️ **Important**: It must be `http://localhost:8501` (not `localhost:8501`, not `/auth/callback`, just the base URL)

### Step 2: Verify .env Configuration

Make sure your `.env` file has:

```
GITHUB_TOKEN=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
CLIENT_ID=Ov23lit1oMOSKbKnId5J
CLIENT_SECRET=4f9d3a6cadddb7806349e369745820ebb7c809c6
OAUTH_REDIRECT_URI=http://localhost:8501
```

### Step 3: Restart Streamlit

```bash
cd dashboard
streamlit run app.py
```

### Step 4: Test the Flow

1. Open http://localhost:8501 in your browser
2. Click "🔗 Sign in with GitHub"
3. You'll be redirected to GitHub
4. Click "Authorize" 
5. You'll be redirected back to CascadeGuard
6. You should see "✅ Successfully signed in with GitHub!"
7. Select a repository from the dropdown
8. Click "🚀 Run Live Analysis"

### Troubleshooting

**Still getting 404?**
- Double-check that GitHub's callback URL is exactly `http://localhost:8501` (no trailing slash, no path)
- Check that CLIENT_ID and CLIENT_SECRET are correct
- Restart Streamlit after making changes

**Getting "Invalid OAuth state" error?**
- This is a security check. Shouldn't happen in normal flow
- Clear browser cookies for localhost and try again

**"Loading repositories..." shows but nothing loads?**
- Check the Streamlit terminal for error messages
- Verify your GitHub token has repo access
- Try signing out and signing back in

### For Production Deployment

When deploying to production (e.g., `https://cascadeguard.your-company.com`):

1. Update GitHub OAuth app:
   - Authorization callback URL: `https://cascadeguard.your-company.com`

2. Update `.env`:
   ```
   OAUTH_REDIRECT_URI=https://cascadeguard.your-company.com
   ```

3. Restart the app

That's it! The OAuth flow will automatically use the new URL.
