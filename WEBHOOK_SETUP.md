"""
┌─────────────────────────────────────────────────────────────────────────────┐
│ PENTAS AGENT — GitHub App Webhook Integration                              │
│ Complete setup guide for automated security scanning on PRs                 │
└─────────────────────────────────────────────────────────────────────────────┘

This document provides step-by-step instructions to set up the GitHub webhook
integration for the PENTAS Security Analysis Agent.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 1: SETUP YOUR GITHUB APP (Manual — github.com)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📝 Step 1: Create the GitHub App

1. Go to: https://github.com/settings/apps
2. Click: "New GitHub App"
3. Fill in:
   - App name: pentas-agent
   - Homepage URL: http://localhost:8000
   - Webhook URL: (temporary) https://example.com/github/webhook
   - Webhook secret: pentas_secret_123

📋 Step 2: Configure Permissions

Repository Permissions (REQUIRED):
  ✓ Contents → Read
  ✓ Pull requests → Read & Write
  ✓ Metadata → Read (default)

Subscribe to events:
  ✓ Pull request

Install settings:
  ✓ Any account

4. Click: "Create GitHub App"

🔐 Step 3: Save Credentials

After creation, you'll see your app page:

1. Copy "App ID" (e.g., 123456)
2. Click "Generate private key" → downloads .pem file
3. Save the .pem file to: backend/private-key.pem

IMPORTANT: Keep the private key SECRET. Do not commit it to git.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 2: INSTALL APP ON YOUR REPO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Go to your app page (https://github.com/apps/pentas-agent)
2. Click "Install App"
3. Select your GitHub account
4. Choose repository: SECURITY_ANALYSIS_AI_AGENT
5. Click "Install"

✅ Done! The app is now installed on your repo.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 3: LOCAL DEVELOPMENT SETUP (Your machine)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📦 Step 1: Install Dependencies

pip install -e .

(or if you modified pyproject.toml)
pip install --upgrade fastapi uvicorn pydantic httpx PyJWT cryptography

✅ If you see "Successfully installed..." you're good to go.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 4: SETUP NGROK (Public URL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPORTANT: GitHub needs a PUBLIC URL to send webhooks.
This is where ngrok comes in.

🔧 Step 1: Install ngrok

Option A (Linux/Mac):
  sudo snap install ngrok
  (or download from https://ngrok.com/download)

Option B (Manual):
  - Download from https://ngrok.com/download
  - Extract to your PATH

🔗 Step 2: Create Public URL

Run:
  ngrok http 8000

OUTPUT WILL LOOK LIKE:
  ┌──────────────────────────────────────────┐
  │ Session Status    online               │
  │ Account          Your Account           │
  │ Version           3.0.0                 │
  │ Region            us (United States)    │
  │ Latency           12 ms                 │
  │ Web Interface     http://127.0.0.1:4040│
  ├──────────────────────────────────────────┤
  │ Forwarding    https://abc123.ngrok-free.app →  http://localhost:8000 │
  └──────────────────────────────────────────┘

COPY: https://abc123.ngrok-free.app (your PUBLIC URL)

⚠️  Every time you restart ngrok, you get a new URL!
    (unless you have a paid plan)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 5: CONFIGURE ENVIRONMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📝 Step 1: Create .env file

Copy the example:
  cp .env.example .env

📝 Step 2: Fill in your credentials

Edit .env:
  GITHUB_APP_ID=123456                    (from GitHub)
  GITHUB_PRIVATE_KEY_PATH=backend/private-key.pem
  GITHUB_WEBHOOK_SECRET=pentas_secret_123

Optional (for advanced analysis):
  OPENAI_API_KEY=sk-...   (if using OpenAI)
  LLM_PROVIDER=openai      (if using LLM)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 6: UPDATE WEBHOOK URL IN GITHUB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Go to: https://github.com/settings/apps/pentas-agent → Edit
2. Find "Webhook URL"
3. Replace:
     https://example.com/github/webhook
   With:
     https://abc123.ngrok-free.app/github/webhook
4. Click "Save changes"

✅ Webhook is now pointed at YOUR LOCAL SERVER!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 7: START THE SERVER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

In your project directory:

  cd /path/to/SECURITY_ANALYSIS_AI_AGENT
  python -m uvicorn backend.webhook_server:app --reload --port 8000

OUTPUT:
  INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
  INFO:     Application startup complete

✅ Server is running AND ngrok is forwarding traffic!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 8: VERIFY WEBHOOK CONNECTIVITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧪 Test 1: Health Check

Open browser or curl:
  curl https://abc123.ngrok-free.app/health

EXPECTED:
  {"status":"ok","github_app_configured":true}

✅ If you see this, the server is reachable!

🧪 Test 2: Test Webhook Endpoint

On GitHub, go to your app → Advanced → Webhooks

You should see a section "Recent deliveries"

If empty, move to test 3...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 9: TRIGGER FIRST WEBHOOK EVENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To trigger the webhook, you need to create a PR event:

Option 1 (Recommended):
  1. Create a new branch in your repo
  2. Make a small change (e.g., add a comment)
  3. Push the branch
  4. Create a Pull Request
  5. GitHub will send a webhook event → your server

Option 2 (Update existing PR):
  1. Push a new commit to an existing PR branch
  2. GitHub sends "synchronize" webhook event

📊 Within 10-30 seconds:
  - Check your server logs (terminal)
  - You should see: "Received webhook event: pull_request"
  - Then: "Analyzing owner/repo PR #N"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 10: VERIFY WEBHOOK DELIVERY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Go to: https://github.com/apps/pentas-agent
2. Click: "Advanced" → "Webhooks"
3. Scroll to "Recent deliveries"

You should see:
  ✓ POST /github/webhook
  ✓ Status: 200 OK (or 202 Accepted)
  ✓ Timestamp: just now

If you see 401/403:
  → Check GitHub App ID & webhook secret in .env

If you see 200 but no comment on PR:
  → Check server logs for errors
  → Run: python -m uvicorn backend.webhook_server:app --reload --port 8000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PART 11: CHECK PR COMMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

If everything worked, you should see:

🔍 **Security Analysis Results**

Scanned 5 file(s) — 0 finding(s) detected.

OR if vulnerabilities found:

🔍 **Security Analysis Results**

Scanned 5 file(s) — 3 finding(s) detected:

### HIGH
- SQL Injection Risk (file.py:42)
- ...

(The comments appear automatically!)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TROUBLESHOOTING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ Issue: "webhook hitting timeout"
✔ Solution:
  - Ensure ngrok is running: ngrok http 8000
  - Ensure server is running: python -m uvicorn ...
  - Check if localhost:8000 is accessible

❌ Issue: "signature verification failed"
✔ Solutions:
  - Verify GITHUB_WEBHOOK_SECRET matches GitHub app settings
  - Ensure you're using the EXACT secret (copy-paste)

❌ Issue: "No comment appearing on PR"
✔ Solutions:
  1. Check server logs for errors
  2. Verify GitHub App has "Pull requests → Read & Write" permission
  3. Verify app is installed: https://github.com/account/installations
  4. Try creating a NEW PR (not updating existing)

❌ Issue: "404 error in webhook delivery"
✔ Solutions:
  - Webhook URL must end with: /github/webhook
  - If using domain, ensure it's public and accessible
  - Check ngrok is forwarding: https://... → http://localhost:8000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEXT STEPS (After Webhook is Working)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Once you see comments on PRs:

1. **Deploy to Production**
   - Replace ngrok with a real domain (AWS, Heroku, etc.)
   - Update webhook URL in GitHub settings

2. **Add Advanced Features**
   - Line-level comments for specific findings
   - PR status checks (approve/block PRs)
   - Detailed vulnerability reports

3. **Customize Analysis**
   - Enable LLM-based analysis (not just tools)
   - Adjust severity thresholds
   - Add custom rules

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ARCHITECTURE OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

User creates PR on GitHub
           ↓
GitHub sends webhook → ngrok public URL
           ↓
ngrok forwards → localhost:8000/github/webhook
           ↓
FastAPI validates signature
           ↓
Extracts PR info (files, commits, etc.)
           ↓
Clones repo and checks out PR branch
           ↓
Runs security scan on changed files
           ↓
Posts results as PR comment ← User sees feedback!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FILES CREATED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

backend/
  ├── __init__.py              (Package marker)
  ├── github_service.py        (GitHub API client)
  └── webhook_server.py        (FastAPI app)

.env.example                   (Configuration template)
.env                          (Your credentials — keep secret!)

private-key.pem              (Downloaded from GitHub — keep secret!)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HELPFUL COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Start the webhook server
python -m uvicorn backend.webhook_server:app --reload --port 8000

# Start ngrok
ngrok http 8000

# Check if server is running
curl http://localhost:8000/health

# View server logs (if running in background)
tail -f webhook_server.log

# Test webhook signature verification
python -c "from backend.github_service import GitHubService; ..."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# This docstring serves as documentation
if __name__ == "__main__":
    print(__doc__)
