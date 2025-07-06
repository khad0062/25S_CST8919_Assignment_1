# Flask Auth0 Web App with Azure Security Monitoring

This lab demonstrates a secure Flask web application with Auth0 authentication and comprehensive Azure security monitoring. The application includes logging, threat detection, and automated alerting for suspicious access patterns.


## Setup Instructions

### 1. Auth0 Configuration

#### 1.1 Create Auth0 Application
1. Go to [Auth0 Dashboard](https://auth0.com) and sign up/login
2. Create a new **Regular Web Application**
3. Note down:
   - **Domain**: `your-tenant.auth0.com`
   - **Client ID**: `your-client-id`
   - **Client Secret**: `your-client-secret`

#### 1.2 Configure Auth0 Application Settings
1. **Allowed Callback URLs**: 
   - Local: `http://localhost:3000/callback`
   - Azure: `https://your-app-name.azurewebsites.net/callback`
2. **Allowed Logout URLs**:
   - Local: `http://localhost:3000`
   - Azure: `https://your-app-name.azurewebsites.net`
3. **Allowed Web Origins**:
   - Local: `http://localhost:3000`
   - Azure: `https://your-app-name.azurewebsites.net`

#### 1.3 Create Auth0 User
1. Go to **User Management** → **Users**
2. Create a test user with email/password
3. Note down the **User ID** for testing

### 2. Azure Configuration

#### 2.1 Create Azure Web App
1. Go to [Azure Portal](https://portal.azure.com)
2. Create **App Service** → **Web App**
3. Configure:
   - **Runtime**: Python 3.11
   - **Operating System**: Linux
   - **Region**: East US (or preferred)
4. Note down the **App URL**: `https://your-app-name.azurewebsites.net`

#### 2.2 Create Log Analytics Workspace
1. Create **Log Analytics Workspace**
2. Note down:
   - **Workspace ID**
   - **Workspace Key**
3. Connect to your Web App:
   - Go to **App Service** → **Monitoring** → **Diagnostic settings**
   - Add diagnostic setting
   - Select **AppServiceHTTPLogs** and **AppServiceConsoleLogs**
   - Send to Log Analytics workspace

#### 2.3 Configure Application Settings
In your Azure Web App → **Configuration** → **Application settings**, add:
```
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_BASE_URL=https://your-app-name.azurewebsites.net
SECRET_KEY=your-secret-key-here
```

### 3. Local Development Setup

#### 3.1 Clone and Setup
```bash
# Clone the repository
git clone <repository-url>
cd 01-login

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 3.2 Environment Configuration
Create `.env` file in the project root:
```env
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_BASE_URL=http://localhost:3000
SECRET_KEY=your-secret-key-here
```

#### 3.3 Run Locally
```bash
python server.py
```
Access the app at: `http://localhost:3000`

### 4. Azure Deployment

#### 4.1 Using Azure CLI
```bash
# Login to Azure
az login

# Deploy to Azure Web App
az webapp deployment source config-zip \
  --resource-group your-resource-group \
  --name your-app-name \
  --src deployment.zip
```

#### 4.2 Using Docker
```bash
# Build and run locally
docker build -t flask-auth0-app .
docker run -p 3000:3000 --env-file .env flask-auth0-app

# Deploy to Azure Container Registry (optional)
az acr build --registry your-registry --image flask-auth0-app .
```

## Application Features

### Authentication Flow
1. **Public Routes**: `/` (home page)
2. **Protected Routes**: `/protected` (requires Auth0 login)
3. **Auth Routes**: `/login`, `/logout`, `/callback`

### Security Features
- **Auth0 Integration**: Secure OAuth2/OpenID Connect authentication
- **Session Management**: Secure session handling with Flask-Session
- **CSRF Protection**: Built-in CSRF protection
- **Security Headers**: Implemented security headers
- **Rate Limiting**: Protection against brute force attacks

## Logging and Monitoring

### Logging Implementation

The application implements comprehensive logging for security monitoring:

#### 1. **Successful Authentication Logs**
```python
# When user successfully accesses protected route
app.logger.info(f"Access to protected route - User ID: {user_id}, IP: {client_ip}")
```

#### 2. **Unauthorized Access Logs**
```python
# When unauthorized user tries to access protected route
app.logger.warning(f"Unauthorized access attempt to /protected - IP: {client_ip}")
```

#### 3. **Authentication Flow Logs**
```python
# Login attempts
app.logger.info(f"Login attempt - IP: {client_ip}")

# Successful logins
app.logger.info(f"Successful login - User ID: {user_id}, IP: {client_ip}")

# Logout events
app.logger.info(f"User logout - User ID: {user_id}, IP: {client_ip}")
```

### Log Structure
Each log entry includes:
- **Timestamp**: ISO format timestamp
- **Level**: INFO, WARNING, ERROR
- **Message**: Descriptive message
- **User ID**: Auth0 user identifier (when available)
- **IP Address**: Client IP address
- **Action**: Specific action taken

### Azure Log Analytics Integration
- **AppServiceHTTPLogs**: HTTP request logs
- **AppServiceConsoleLogs**: Application console logs
- **Real-time Streaming**: Logs appear in Azure within 2-5 minutes
- **Retention**: 30 days (configurable)

## Detection Logic

### Threat Detection Patterns

#### 1. **Excessive Access Pattern**
- **Threshold**: >10 accesses to `/protected` in 15 minutes
- **Detection**: KQL query aggregates access counts per user
- **Response**: Automated alert with user details

#### 2. **Unauthorized Access Attempts**
- **Pattern**: Multiple failed authentication attempts
- **Detection**: Monitoring 401/403 responses
- **Response**: Security team notification

#### 3. **Suspicious User Agents**
- **Pattern**: Bot-like or malicious user agents
- **Detection**: Pattern matching in user agent strings
- **Response**: Enhanced monitoring

#### 4. **Geographical Anomalies**
- **Pattern**: Access from unusual locations
- **Detection**: IP geolocation analysis
- **Response**: Additional verification required

### Detection Algorithm

```python
def detect_suspicious_activity(user_id, time_window=15):
    """
    Detect suspicious access patterns
    
    Args:
        user_id: Auth0 user identifier
        time_window: Time window in minutes
    
    Returns:
        bool: True if suspicious activity detected
    """
    access_count = count_protected_access(user_id, time_window)
    
    if access_count > 10:
        return True
    
    return False
```

## KQL Queries and Alert Logic

### Primary Detection Query

```kusto
AppServiceHTTPLogs
| union AppServiceConsoleLogs
| where TimeGenerated >= ago(15m)
| where ResultDescription contains "Access to protected route" or CsUriStem == "/protected"
| extend UserInfo = extract("User ID: ([^,]+)", 1, ResultDescription)
| extend user_id = coalesce(UserInfo, strcat("ip_", tostring(hash(CIp))))
| where isnotempty(user_id)
| summarize access_count = count(), timestamp = max(TimeGenerated) by user_id
| where access_count > 10
| project user_id, timestamp, access_count
| order by access_count desc
```

### Query Logic Explanation

#### 1. **Data Source Union**
```kusto
AppServiceHTTPLogs | union AppServiceConsoleLogs
```
- Combines HTTP logs and console logs
- Ensures comprehensive coverage of all access attempts

#### 2. **Time Window Filter**
```kusto
| where TimeGenerated >= ago(15m)
```
- Analyzes only the last 15 minutes
- Rolling window for real-time detection

#### 3. **Route-Specific Filter**
```kusto
| where ResultDescription contains "Access to protected route" or CsUriStem == "/protected"
```
- Filters for `/protected` route access
- Includes both successful and failed attempts

#### 4. **User Identification**
```kusto
| extend UserInfo = extract("User ID: ([^,]+)", 1, ResultDescription)
| extend user_id = coalesce(UserInfo, strcat("ip_", tostring(hash(CIp))))
```
- Extracts Auth0 user ID from log messages
- Falls back to hashed IP address for anonymous users
- Ensures all access attempts are attributed to an identifier

#### 5. **Aggregation and Filtering**
```kusto
| summarize access_count = count(), timestamp = max(TimeGenerated) by user_id
| where access_count > 10
```
- Counts accesses per user within the time window
- Filters for users exceeding the threshold (10 accesses)

### Additional Monitoring Queries

#### Real-time Activity Monitor
```kusto
AppServiceHTTPLogs
| where TimeGenerated >= ago(5m)
| where CsUriStem == "/protected"
| project TimeGenerated, CIp, CsUserAgent, ScStatus
| order by TimeGenerated desc
```

#### Failed Authentication Attempts
```kusto
AppServiceConsoleLogs
| where TimeGenerated >= ago(30m)
| where ResultDescription contains "Unauthorized access attempt"
| summarize attempts = count() by bin(TimeGenerated, 5m)
| render timechart
```

#### Geographic Distribution
```kusto
AppServiceHTTPLogs
| where TimeGenerated >= ago(1h)
| where CsUriStem == "/protected"
| summarize requests = count() by CIp
| evaluate ipv4_lookup(geo_info_from_ip_address, CIp)
| project CIp, requests, country, region, city
```

## Azure Alert Configuration

### Alert Rule Setup

#### 1. **Basic Information**
- **Name**: "Suspicious /protected Route Access"
- **Description**: "Detects users accessing /protected route more than 10 times in 15 minutes"
- **Severity**: 3 (Low)
- **Resource**: Log Analytics Workspace

#### 2. **Condition Configuration**
```json
{
  "query": "AppServiceHTTPLogs | union AppServiceConsoleLogs | where TimeGenerated >= ago(15m) | where ResultDescription contains \"Access to protected route\" or CsUriStem == \"/protected\" | extend UserInfo = extract(\"User ID: ([^,]+)\", 1, ResultDescription) | extend user_id = coalesce(UserInfo, strcat(\"ip_\", tostring(hash(CIp)))) | where isnotempty(user_id) | summarize access_count = count(), timestamp = max(TimeGenerated) by user_id | where access_count > 10 | project user_id, timestamp, access_count | order by access_count desc",
  "timeAggregation": "Count",
  "operator": "GreaterThan",
  "threshold": 0,
  "frequency": "PT5M",
  "period": "PT15M"
}
```

#### 3. **Alert Logic**
- **Evaluation Frequency**: Every 5 minutes
- **Lookback Period**: 15 minutes
- **Threshold**: Greater than 0 results
- **Condition**: Number of search results

#### 4. **Action Group**
```json
{
  "name": "SecurityTeamNotification",
  "actions": [
    {
      "type": "Email",
      "emailAddress": "security@company.com",
      "subject": "ALERT: Suspicious Access Pattern Detected"
    },
    {
      "type": "SMS",
      "phoneNumber": "+1234567890"
    }
  ]
}
```

### Alert Workflow

1. **Detection**: KQL query runs every 5 minutes
2. **Evaluation**: Checks for results > 0
3. **Trigger**: Alert fires if condition is met
4. **Notification**: Action group sends email/SMS
5. **Escalation**: Manual review by security team

## Testing and Validation

### Traffic Simulation

#### 1. **Using test-app.http**
```http
# Valid access with Auth0 token
GET https://your-app.azurewebsites.net/protected
Authorization: Bearer {{valid_token}}

# Invalid access (no token)
GET https://your-app.azurewebsites.net/protected
```

#### 2. **Using PowerShell Script**
```powershell
.\test-azure-webapp.ps1 -NumberOfRequests 15 -DelayBetweenRequests 3
```

#### 3. **Manual Testing**
1. Open browser and navigate to `/protected`
2. Complete Auth0 login
3. Refresh the page multiple times rapidly
4. Check Azure logs for entries

### Validation Steps

1. **Run Traffic Simulation**: Generate >10 requests in 15 minutes
2. **Check Logs**: Verify entries in Log Analytics
3. **Validate Query**: Run KQL query manually
4. **Confirm Alert**: Check Azure Monitor for fired alerts
5. **Verify Notification**: Confirm email/SMS received

## Project Structure

```
01-login/
├── server.py                    # Main Flask application
├── requirements.txt             # Python dependencies
├── Dockerfile                  # Docker configuration
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore rules
├── README.md                  # This documentation
├── templates/
│   ├── home.html             # Home page template
│   └── protected.html        # Protected page template
├── test-app.http             # HTTP requests for testing
├── test-azure-webapp.ps1     # PowerShell test script
├── simple-traffic-test.ps1   # Alternative test script
├── KQL_QUERIES_AND_ALERTS.md # KQL queries documentation
└── TRAFFIC_SIMULATION_AND_ALERTS.md # Testing documentation
```

## Configuration Reference

### Environment Variables
| Variable | Description | Example |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `abc123...` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `xyz789...` |
| `AUTH0_DOMAIN` | Auth0 tenant domain | `tenant.auth0.com` |
| `AUTH0_BASE_URL` | Application base URL | `https://app.azurewebsites.net` |
| `SECRET_KEY` | Flask secret key | `random-secret-key` |

### Flask Configuration
```python
# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Auth0 Configuration
app.config['AUTH0_CLIENT_ID'] = os.environ.get('AUTH0_CLIENT_ID')
app.config['AUTH0_CLIENT_SECRET'] = os.environ.get('AUTH0_CLIENT_SECRET')
app.config['AUTH0_DOMAIN'] = os.environ.get('AUTH0_DOMAIN')
```

## Security Considerations

### Authentication Security
- **OAuth2/OpenID Connect**: Industry-standard authentication
- **Secure Tokens**: JWT tokens with proper validation
- **Session Management**: Secure session handling
- **CSRF Protection**: Built-in protection mechanisms

### Application Security
- **Input Validation**: Sanitized user inputs
- **Security Headers**: Implemented security headers
- **HTTPS Only**: Enforced HTTPS in production
- **Rate Limiting**: Protection against abuse

### Monitoring Security
- **Log Integrity**: Tamper-evident logging
- **Data Privacy**: No sensitive data in logs
- **Access Control**: Restricted log access
- **Retention Policy**: Appropriate log retention

## Deployment Checklist

### Pre-Deployment
- [ ] Auth0 application configured
- [ ] Azure Web App created
- [ ] Log Analytics workspace set up
- [ ] Environment variables configured
- [ ] SSL certificate configured

### Post-Deployment
- [ ] Application accessible via HTTPS
- [ ] Auth0 login flow working
- [ ] Logs appearing in Azure
- [ ] KQL queries returning results
- [ ] Alert rules configured and tested
- [ ] Action groups configured
- [ ] Notifications working

### Monitoring Setup
- [ ] Log Analytics workspace connected
- [ ] Diagnostic settings configured
- [ ] KQL queries validated
- [ ] Alert rules created
- [ ] Action groups configured
- [ ] Test alerts fired successfully

## Troubleshooting

### Common Issues

#### 1. **Auth0 Login Not Working**
- Check callback URLs in Auth0 dashboard
- Verify environment variables
- Check domain configuration

#### 2. **Logs Not Appearing**
- Verify diagnostic settings
- Check Log Analytics workspace connection
- Wait 5-10 minutes for log propagation

#### 3. **Alerts Not Firing**
- Validate KQL query manually
- Check alert rule configuration
- Verify Action Group settings

#### 4. **No Email Notifications**
- Check Action Group configuration
- Verify email address
- Check spam folder

### Debug Commands

```bash
# Check environment variables
env | grep AUTH0

# Test application locally
python server.py

# Check Azure logs
az webapp log tail --name your-app-name --resource-group your-rg

# Test KQL query
az monitor log-analytics query --workspace your-workspace --analytics-query "your-query"
```

## Additional Resources

### Documentation
- [Auth0 Documentation](https://auth0.com/docs)
- [Azure App Service Documentation](https://docs.microsoft.com/azure/app-service/)
- [Azure Monitor Documentation](https://docs.microsoft.com/azure/azure-monitor/)
- [KQL Reference](https://docs.microsoft.com/azure/data-explorer/kusto/query/)

### Tools
- [Auth0 Dashboard](https://manage.auth0.com)
- [Azure Portal](https://portal.azure.com)
- [Azure CLI](https://docs.microsoft.com/cli/azure/)
- [VS Code REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation links

---

**Note**: This is a learning project for CST8919 Assignment 1. Always follow security best practices in production environments.
