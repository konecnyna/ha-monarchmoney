# Troubleshooting Monarch Money Integration

## HTTP 525 SSL Handshake Failed Error

### Symptoms
- Integration fails to connect with error: `SSL handshake failed (525)`
- Logs show: `Python 3.13.x, OpenSSL 3.5.x`
- Error message: "The custom SSL configuration could not establish a secure connection"

### Root Cause

**OpenSSL 3.5.0 and newer versions have a known incompatibility with Cloudflare** that causes SSL handshake failures (HTTP 525 errors). This is a protocol-level issue that cannot be resolved with cipher suite configuration alone.

**Your environment is affected if you have:**
- Python 3.13.0+ with OpenSSL 3.5.0+
- Home Assistant OS 2025.x or newer (which ships with Python 3.13+)

### Workaround: Disable SSL Verification (Temporary)

⚠️ **WARNING**: This workaround disables SSL certificate verification, which reduces security. Only use this as a temporary solution until the OpenSSL/Cloudflare incompatibility is resolved.

#### For Home Assistant OS / Supervised:

1. **Add environment variable** to Home Assistant configuration:

Edit `/config/configuration.yaml` and add:

```yaml
homeassistant:
  # ... other settings ...

# Add this anywhere in the file (top level)
environment:
  MONARCHMONEY_DISABLE_SSL_VERIFY: "1"
```

2. **Restart Home Assistant** completely (not just reload)

3. **Reconfigure the integration**
   - Go to Settings → Devices & Services
   - Find Monarch Money integration
   - Re-enter your credentials

4. **Check logs** for this message:
   ```
   WARNING: ⚠️ SSL VERIFICATION DISABLED via MONARCHMONEY_DISABLE_SSL_VERIFY environment variable
   INFO: Created unverified SSL context (SSL verification disabled)
   ```

#### For Home Assistant Container (Docker):

Add environment variable to your docker-compose.yml:

```yaml
services:
  homeassistant:
    container_name: homeassistant
    image: homeassistant/home-assistant:latest
    environment:
      - MONARCHMONEY_DISABLE_SSL_VERIFY=1
    # ... rest of config ...
```

Or add to `docker run` command:
```bash
docker run -e MONARCHMONEY_DISABLE_SSL_VERIFY=1 ...
```

#### For Home Assistant Core (Python venv):

Set environment variable before starting Home Assistant:

```bash
export MONARCHMONEY_DISABLE_SSL_VERIFY=1
hass
```

Or add to systemd service file (`/etc/systemd/system/home-assistant@homeassistant.service`):

```ini
[Service]
Environment="MONARCHMONEY_DISABLE_SSL_VERIFY=1"
```

### Alternative Solutions

#### 1. Downgrade OpenSSL (Advanced)

If you're using Home Assistant Core in a Python virtual environment, you could potentially downgrade OpenSSL from 3.5.x to 3.4.x. **This is not possible with Home Assistant OS/Supervised**.

#### 2. Wait for Fix

Monitor these resources for updates:
- [OpenSSL Project](https://github.com/openssl/openssl/issues)
- [Cloudflare Community](https://community.cloudflare.com)
- This integration's [GitHub Issues](https://github.com/konecnyna/ha-monarchmoney/issues)

#### 3. Contact Monarch Money

Report the issue to Monarch Money support and request they investigate the OpenSSL 3.5/Cloudflare compatibility issue.

---

## Other Common Issues

### 403 Forbidden Error

**Symptoms:**
- Integration fails with "403 Forbidden" error
- Usually occurs after MFA setup

**Solution:**
1. Ensure MFA TOTP secret is correctly entered
2. Try removing and re-adding the integration
3. Check that your Monarch Money account is active and not locked

### Rate Limiting (429 Error)

**Symptoms:**
- Error: "Rate limited by Monarch Money API"

**Solution:**
- Wait 5-10 minutes before retrying
- Reduce polling frequency in integration settings if available

### MFA Issues

**Symptoms:**
- "Multi-Factor Auth Required" error
- Integration asks for MFA code repeatedly

**Solution:**
1. Obtain your TOTP secret key from Monarch Money settings
2. Enter the full TOTP secret (not just the 6-digit code) in integration config
3. Ensure system time is synchronized correctly

---

## Getting Help

If none of these solutions work:

1. **Enable debug logging**:
   ```yaml
   logger:
     default: info
     logs:
       custom_components.monarchmoney: debug
   ```

2. **Collect information**:
   - Python version (from logs)
   - OpenSSL version (from logs)
   - Full error traceback
   - Home Assistant version

3. **Report issue**:
   - GitHub: https://github.com/konecnyna/ha-monarchmoney/issues
   - Include the information from step 2
   - Remove any sensitive credentials from logs

---

## Security Notes

### SSL Verification Workaround

When you use `MONARCHMONEY_DISABLE_SSL_VERIFY=1`:
- ❌ SSL certificates are NOT verified
- ❌ Man-in-the-middle attacks are possible
- ❌ Your Monarch Money credentials could be intercepted
- ✅ Only your local network is affected (not other integrations)

**Best practices:**
- Only use on trusted networks
- Remove the environment variable once the OpenSSL/Cloudflare issue is resolved
- Monitor for updates to this integration

### Why is this necessary?

The OpenSSL 3.5.0+ and Cloudflare incompatibility is a known issue affecting many applications, not just this integration. The protocol-level handshake failure cannot be fixed at the application layer without either:
1. Downgrading OpenSSL (not feasible in HA OS)
2. Bypassing SSL verification (security trade-off)
3. Waiting for OpenSSL 3.5.x or Cloudflare to fix the incompatibility

---

**Last Updated**: January 2026
**Integration Version**: 1.2.4+
**Affected**: Python 3.13.x with OpenSSL 3.5.x
