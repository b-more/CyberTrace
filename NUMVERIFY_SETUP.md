# Numverify API Integration Setup

## What is Numverify?

Numverify is a professional phone number validation and lookup API that provides:
- ✅ Carrier/Network Provider information
- ✅ Line Type (Mobile, Landline, VoIP)
- ✅ Location and Country details
- ✅ Phone number validation
- ✅ International format verification

## Free Tier

- **100 API calls per month** (free)
- Perfect for investigating phone numbers in criminal cases
- No credit card required for free tier

## Setup Instructions

### Step 1: Sign Up for Numverify

1. Go to: https://numverify.com/
2. Click "Get Free API Key" or "Sign Up"
3. Create a free account with your email
4. Verify your email address
5. Login to your dashboard

### Step 2: Get Your API Key

1. After logging in, go to your dashboard
2. You'll see your API key displayed
3. Copy the API key (it looks like: `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`)

### Step 3: Add API Key to CyberTrace

1. Open the `.env` file in the CyberTrace directory:
   ```bash
   nano /var/www/html/projects/CyberTrace/.env
   ```

2. Find the line:
   ```
   NUMVERIFY_API_KEY=your_numverify_api_key_here
   ```

3. Replace `your_numverify_api_key_here` with your actual API key:
   ```
   NUMVERIFY_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
   ```

4. Save the file (Ctrl+X, then Y, then Enter in nano)

5. Restart the Flask application:
   ```bash
   pkill -f "python run.py"
   cd /var/www/html/projects/CyberTrace
   source venv/bin/activate
   nohup python run.py > /tmp/cybertracer_app.log 2>&1 &
   ```

### Step 4: Test Integration

1. Run a phone investigation
2. Look for the green badge "Enhanced by Numverify API" in the Carrier Information section
3. You'll see additional fields like:
   - More accurate carrier name
   - Line type (MOBILE, LANDLINE, etc.)
   - Enhanced location data
   - Verification status

## What You'll Get

**Without Numverify:**
- Basic carrier info from phonenumbers library
- Limited accuracy
- Basic validation

**With Numverify:**
- ✅ Professional carrier database
- ✅ Accurate line type detection
- ✅ Enhanced location information
- ✅ Verified phone number data
- ✅ "Enhanced by Numverify API" badge in results

## Usage Monitoring

- Free tier: 100 calls/month
- Track usage in your Numverify dashboard
- Each phone investigation = 1 API call
- Plan accordingly for your caseload

## Troubleshooting

### API key not working?
- Check that you copied the entire key
- Make sure there are no extra spaces
- Verify the key is active in your Numverify dashboard

### Not seeing enhanced data?
- Check `.env` file has correct API key
- Restart Flask application after changing `.env`
- Check logs: `tail -f /tmp/cybertracer_app.log`

### Exceeded free tier?
- Upgrade to paid plan ($9.99/month for 5,000 requests)
- Or wait until next month for free tier reset

## Support

- Numverify Documentation: https://numverify.com/documentation
- Numverify Support: support@apilayer.com
- CyberTrace Integration: Check app logs for errors

