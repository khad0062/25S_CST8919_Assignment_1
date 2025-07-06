# Assignment 1: Securing and Monitoring an Authenticated Flask App

This assignment demonstrates a secure Flask web application with Auth0 authentication and comprehensive Azure security monitoring. The application includes logging, threat detection, and automated alerting for suspicious access patterns.

## Setup Instructions

### 1. Auth0 Configuration

#### Create Auth0 Application
1. Go to [Auth0 Dashboard](https://auth0.com) and sign up/login
2. Create a new **Regular Web Application**
3. Note down:
   - **Domain**: `your-tenant.auth0.com`
   - **Client ID**: `your-client-id`
   - **Client Secret**: `your-client-secret`

#### Configure Auth0 Application Settings
1. **Allowed Callback URLs**: 
   - Local: `http://localhost:3000/callback`
   - Azure: `https://your-app-name.azurewebsites.net/callback`
2. **Allowed Logout URLs**:
   - Local: `http://localhost:3000`
   - Azure: `https://your-app-name.azurewebsites.net`

### 2. Azure Configuration

#### Create Azure Web App
1. Go to [Azure Portal](https://portal.azure.com)
2. Create **App Service** → **Web App**
3. Configure:
   - **Runtime**: Python 3.11
   - **Operating System**: Linux

#### Create Log Analytics Workspace
1. Create **Log Analytics Workspace**
2. Connect to your Web App:
   - Go to **App Service** → **Monitoring** → **Diagnostic settings**
   - Add diagnostic setting
   - Select **AppServiceHTTPLogs** and **AppServiceConsoleLogs**
   - Send to Log Analytics workspace

#### Configure Application Settings
In your Azure Web App → **Configuration** → **Application settings**, add:
```
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_BASE_URL=https://your-app-name.azurewebsites.net
SECRET_KEY=your-secret-key-here
```

### 3. Environment Configuration

#### Local Development
Create `.env` file in the project root:
```env
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_BASE_URL=http://localhost:3000
SECRET_KEY=your-secret-key-here
```

#### Install Dependencies and Run
```bash
pip install -r requirements.txt
python server.py
```

**Note**: The main Flask application is located in `server.py`. This file contains:
- Auth0 authentication configuration
- Route definitions (`/`, `/login`, `/logout`, `/callback`, `/protected`)
- Logging implementation for security monitoring
- Session management and security middleware

### 4. Deploy to Azure Web App using GitHub

#### Setup GitHub Repository
1. Create a new GitHub repository or use existing one
2. Push your Flask application code to the repository:
```bash
git add .
git commit -m "Initial Flask Auth0 app"
git push origin main
```

#### Configure Azure Deployment
1. Go to your Azure Web App in [Azure Portal](https://portal.azure.com)
2. Navigate to **Deployment** → **Deployment Center**
3. Select **GitHub** as the source
4. Sign in to your GitHub account when prompted
5. Configure the following:
   - **Organization**: Your GitHub username/organization
   - **Repository**: Select your repository
   - **Branch**: `main` (or your default branch)

#### Setup Build Configuration
1. **Build provider**: Select **GitHub Actions**
2. **Runtime stack**: Python 3.11
3. **Version**: 3.11
4. Azure will automatically generate a GitHub Actions workflow file

#### Configure GitHub Actions Workflow
Azure creates a `.github/workflows/main_<your-app-name>.yml` file. Ensure it includes:
```yaml
name: Build and deploy Python app to Azure Web App

on:
  push:
    branches:
      - main
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python version
        uses: actions/setup-python@v1
        with:
          python-version: '3.11'

      - name: Create and start virtual environment
        run: |
          python -m venv venv
          source venv/bin/activate

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Zip artifact for deployment
        run: zip release.zip ./* -r

      - name: Upload artifact for deployment jobs
        uses: actions/upload-artifact@v3
        with:
          name: python-app
          path: |
            release.zip
            !venv/

  deploy:
    runs-on: ubuntu-latest
    needs: build
    environment:
      name: 'Production'
      url: ${{ steps.deploy-to-webapp.outputs.webapp-url }}

    steps:
      - name: Download artifact from build job
        uses: actions/download-artifact@v3
        with:
          name: python-app

      - name: Unzip artifact for deployment
        run: unzip release.zip

      - name: 'Deploy to Azure Web App'
        uses: azure/webapps-deploy@v2
        id: deploy-to-webapp
        with:
          app-name: 'your-app-name'
          slot-name: 'Production'
          publish-profile: ${{ secrets.AZUREAPPSERVICE_PUBLISHPROFILE }}
```

#### Configure Deployment Secrets
1. In Azure Portal, go to your Web App → **Deployment** → **Deployment Center**
2. Copy the **Publish Profile** content
3. In your GitHub repository, go to **Settings** → **Secrets and variables** → **Actions**
4. Create a new secret:
   - **Name**: `AZUREAPPSERVICE_PUBLISHPROFILE`
   - **Value**: Paste the publish profile content

#### Verify Deployment
1. Push any changes to trigger the GitHub Actions workflow:
```bash
git add .
git commit -m "Setup deployment"
git push origin main
```
2. Monitor the deployment in **GitHub Actions** tab
3. Check your Azure Web App URL to verify the deployment

## Logging Implementation

The application implements comprehensive logging for security monitoring:

### Successful Authentication Logs
```python
# When user successfully accesses protected route
app.logger.info(f"Access to protected route - User ID: {user_id}, IP: {client_ip}")
```

### Unauthorized Access Logs
```python
# When unauthorized user tries to access protected route
app.logger.warning(f"Unauthorized access attempt to /protected - IP: {client_ip}")
```

### Authentication Flow Logs
```python
# Login attempts
app.logger.info(f"Login attempt - IP: {client_ip}")

# Successful logins
app.logger.info(f"Successful login - User ID: {user_id}, IP: {client_ip}")

# Logout events
app.logger.info(f"User logout - User ID: {user_id}, IP: {client_ip}")
```

## Detection Logic

### Threat Detection Pattern
- **Threshold**: >10 accesses to `/protected` in 15 minutes
- **Detection**: KQL query aggregates access counts per user
- **Response**: Automated alert with user details


## KQL Query and Alert Logic

### Primary Detection Query
```kusto
AppServiceConsoleLogs
| where TimeGenerated >= ago(15m)
| where ResultDescription has "Access to protected route"
| extend user_id = extract("User ID: ([^,]+)", 1, ResultDescription)
| where isnotempty(user_id)
| summarize access_count = count(), timestamp = max(TimeGenerated) by user_id
| where access_count > 10
| project user_id, timestamp, access_count
| order by access_count desc
```

### Query Logic Explanation

#### 1. **Data Source Selection**
```kusto
AppServiceConsoleLogs
```
- Uses Azure App Service console logs
- Contains application-generated log messages from Flask app

#### 2. **Time Window Filter**
```kusto
| where TimeGenerated >= ago(15m)
```
- Analyzes logs from the last 15 minutes
- Provides sufficient time window to detect patterns

#### 3. **Route-Specific Filter**
```kusto
| where ResultDescription has "Access to protected route"
```
- Filters for log entries containing "Access to protected route"
- Matches the exact log message from Flask application
- Uses `has` operator for efficient text search

#### 4. **User Identification**
```kusto
| extend user_id = extract("User ID: ([^,]+)", 1, ResultDescription)
| where isnotempty(user_id)
```
- Extracts Auth0 user ID from log message using regex pattern
- `([^,]+)` captures everything until the first comma
- Filters out entries where user_id extraction failed
- Ensures only valid user identifiers are processed

#### 5. **Aggregation and Counting**
```kusto
| summarize access_count = count(), timestamp = max(TimeGenerated) by user_id
```
- Groups log entries by user_id
- Counts total accesses per user (`access_count`)
- Records the most recent access time (`timestamp`)

#### 6. **Threshold Filtering**
```kusto
| where access_count > 10
```
- Filters for users who accessed `/protected` more than 10 times
- This threshold indicates suspicious activity

#### 7. **Result Formatting**
```kusto
| project user_id, timestamp, access_count
| order by access_count desc
```
- Selects only relevant columns for output
- Orders results by access count (highest first)
- Shows most suspicious users at the top

### Azure Alert Configuration

#### Alert Rule Setup
- **Name**: "Suspicious /protected Route Access"
- **Description**: "Detects users accessing /protected route more than 10 times in 15 minutes"
- **Severity**: 3 (Low)
- **Resource**: Log Analytics Workspace

#### Alert Logic
- **Evaluation Frequency**: Every 5 minutes
- **Lookback Period**: 15 minutes
- **Threshold**: Greater than 0 results
- **Condition**: Number of search results

#### Action Group
Configure email notifications:
- **Type**: Email
- **Subject**: "ALERT: Suspicious Access Pattern Detected"

### Alert Workflow
1. **Detection**: KQL query runs every 5 minutes
2. **Evaluation**: Checks for results > 0
3. **Trigger**: Alert fires if condition is met
4. **Notification**: Action group sends email
