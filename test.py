from mitmproxy import http, ctx
import re

# Define domain-specific regex patterns
DOMAIN_PATTERNS = {
    "api.stripe.com": [
        rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}",
        rb"card\[cvc\]=[\d]{3,4}",
        rb"source_data\[card\]\[cvc\]=[\d]{3,4}",
        rb"payment_method_data\\[payment_user_agent\\]=[^\\&]*",
        rb"payment_method_data\\[time_on_page\\]=[^\\&]*",
        rb"payment_method_data\\[pasted_fields\\]=[^\\&]*",
        rb"payment_user_agent=[^\\&]*",
        rb"source_data\\[payment_user_agent\\]=[^\\&]*",
        rb"source_data\\[time_on_page\\]=[^\\&]*",
    ],
    "cloud.boosteroid.com": [
        rb"encryptedSecurityCode\":\s*\"[^\"]+\""
    ],
    "api.checkout.com": [
        rb"\"cvv\":\s*\"[\d]{3,4}\""
    ],
    "pci-connect.squareup.com": [
        rb"cvv\":\s*\"[\d]{3,4}\""
    ],
    "checkoutshopper-live.adyen.com": [
        rb"encryptedSecurityCode\":\s*\"[^\"]+\""
    ],
    "payments.vultr.com": [
        rb"cc_cscv=[\d]{3,4}"
    ],
    "payments.braintree-api.com": [
        rb"\"cvv\":\s*\"[\d]{3,4}\""
    ]
}

# Universal patterns for other domains
UNIVERSAL_PATTERNS = [
    rb"payment_method_data\[card\]\[cvc\]=[\d]{3,4}",
    rb"card\[cvc\]=[\d]{3,4}",
    rb"source_data\[card\]\[cvc\]=[\d]{3,4}",
    rb"encryptedSecurityCode\":\s*\"[^\"]+\"",
    rb"\"cvv\":\s*\"[\d]{3,4}\"",
    rb"cc_cscv=[\d]{3,4}",
    rb"card\[cvv\]=[\d]{3,4}",
    rb"card\[cvv2\]=[\d]{3,4}",
    rb"security_code=[\d]{3,4}",
    rb"securityCode=[\d]{3,4}",
    rb"cvvNumber=[\d]{3,4}",
    rb"card_verification_value=[\d]{3,4}",
    rb"cvv_code=[=:\"\s]*\"?[\d]{3,4}\"?",
    rb"csc=[\d]{3,4}",
    rb"cvn=[\d]{3,4}",
    rb"cvv_field=[\d]{3,4}",
    rb"cvc_code=[\d]{3,4}",
    rb"securityNumber=[\d]{3,4}",
    rb"verification_code=[\d]{3,4}",
    rb"verificationCode=[\d]{3,4}",
    rb"card_security_code=[\d]{3,4}",
    rb"cardSecurityCode=[\d]{3,4}",
    rb"cardCvc=[\d]{3,4}",
    rb"cardCvv=[\d]{3,4}",
    rb"cvvValue=[\d]{3,4}",
    rb"cvcValue=[\d]{3,4}",
    rb"cvv_field_value=[\d]{3,4}",
    rb"cvc_field_value=[\d]{3,4}",
    rb"cardVerificationCode=[\d]{3,4}",
    rb"cvcNumber=[\d]{3,4}",
    rb"cvv_num=[\d]{3,4}",
    rb"cvc_num=[\d]{3,4}",
    rb"encrypted\w*Code\":\s*\"[a-zA-Z0-9+/=]+\"",
    rb"cvv_encrypted\":\s*\"[a-zA-Z0-9+/=]+\"",
    rb"cvc_encrypted\":\s*\"[a-zA-Z0-9+/=]+\"",
    rb"payment_method_data\[payment_user_agent\]=[^\&]*",
    rb"payment_method_data\[time_on_page\]=[^\&]*",
    rb"payment_method_data\[pasted_fields\]=[^\&]*",
    rb"payment_user_agent=[^\&]*",
    rb"pasted_fields=[^\&]*",
    rb"time_on_page=[^\&]*",
    rb"source_data\[pasted_fields\]=[^\&]*",
    rb"source_data\[payment_user_agent\]=[^\&]*",
    rb"source_data\[time_on_page\]=[^\&]*"
]

# Define the cvc2 pattern separately
CVC2_PATTERN = re.compile(r"cvc2[=:\"\s]*\"?[\d]{3,4}\"?")

def log_request_body(flow: http.HTTPFlow, message: str, level: str = "info"):
    """
    Logs the request body for debugging purposes.
    """
    log_func = getattr(ctx.log, level, ctx.log.info)
    log_func(f"{message}: {flow.request.content.decode('utf-8', errors='ignore')}")

def clean_up_trailing_characters(request_body: str) -> str:
    """
    Cleans up trailing commas, quotes, or ampersands left behind after removing CVV values and other specified fields.
    """
    cleaned_body = re.sub(r',\s*\"[^\"]*\":\s*\"\"', '', request_body)
    cleaned_body = re.sub(r'[&]?\s*[a-zA-Z0-9_]+\[?[a-zA-Z0-9_]*\]?\=[^\&]*', '', cleaned_body)
    cleaned_body = re.sub(r'[&]$', '', cleaned_body)  # Remove trailing '&' if any
    return cleaned_body

def remove_sensitive_data(request_body: str, patterns: list) -> (str, bool):
    """
    Removes the sensitive data from the request body based on the patterns.
    Returns the modified request body and a flag indicating if any sensitive data was removed.
    """
    data_removed = False
    for pattern in patterns:
        if re.search(pattern, request_body):
            data_removed = True
        request_body = re.sub(pattern, b'', request_body)
    return request_body, data_removed

def remove_cvc2(request_body: str) -> (str, bool):
    """
    Removes the cvc2 data from the request body.
    Returns the modified request body and a flag indicating if any cvc2 data was removed.
    """
    data_removed = False
    if re.search(CVC2_PATTERN, request_body):
        data_removed = True
    request_body = re.sub(CVC2_PATTERN, b'', request_body)
    return request_body, data_removed

def modify_request(flow: http.HTTPFlow):
    """
    Modifies the intercepted request to remove sensitive data.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")
    
    request_body_bytes = flow.request.content
    
    # Determine the patterns to use based on the request URL
    for domain, domain_patterns in DOMAIN_PATTERNS.items():
        if domain in flow.request.url:
            patterns = domain_patterns
            break
    else:
        patterns = UNIVERSAL_PATTERNS

    # Remove sensitive data from the request
    modified_body_bytes, data_removed = remove_sensitive_data(request_body_bytes, patterns)
    
    # Remove cvc2 data if the URL matches specific criteria
    if "https://api.processout.com/cards" in flow.request.url:
        modified_body_bytes, cvc2_removed = remove_cvc2(modified_body_bytes)
        data_removed = data_removed or cvc2_removed
    
    # Clean up any trailing characters if necessary
    modified_body_str = clean_up_trailing_characters(modified_body_bytes.decode('utf-8', errors='ignore'))
    
    # Log the modified request data for debugging
    log_request_body(flow, "Modified Request Body")
    
    # Set the modified body back to the request
    flow.request.content = modified_body_str.encode('utf-8')

def request(flow: http.HTTPFlow):
    """
    This function intercepts and modifies requests to remove sensitive data.
    """
    if flow.request.method in ["POST", "GET", "OPTIONS"]:  # Include GET and OPTIONS requests
        modify_request(flow)

def start():
    """
    Function executed when the proxy starts.
    """
    ctx.log.info("Proxy server started. Ready to intercept requests.")

# Attach handlers to mitmproxy
addons = [
    request
  ]
