from mitmproxy import http, ctx
import re

# Define regex patterns directly within the script
PATTERNS = [
    "payment_method_data\\[card\\]\\[cvc\\][=:][\\d]{3,4}",
    "card\\[cvc\\][=:][\\d]{3,4}",
    "source_data\\[card\\]\\[cvc\\][=:][\\d]{3,4}",
    "encryptedSecurityCode\":\\s*\"[^\"]+\"",
    "\"cvv\"\\s*[:=\\s]*\"?[\\d]{3,4}\"?",
    "cc_cscv[=:][\\d]{3,4}",
    "card\\[cvv\\][=:][\\d]{3,4}",
    "card\\[cvv2\\][=:][\\d]{3,4}",
    "security_code[=:][\\d]{3,4}",
    "securityCode[=:][\\d]{3,4}",
    "cvvNumber[=:][\\d]{3,4}",
    "card_verification_value[=:][\\d]{3,4}",
    "cvv_code[=:\"\\s]*\"?[\\d]{3,4}\"?",
    "csc[=:][\\d]{3,4}",
    "cvn[=:][\\d]{3,4}",
    "cvv_field[=:][\\d]{3,4}",
    "cvc_code[=:][\\d]{3,4}",
    "securityNumber[=:][\\d]{3,4}",
    "verification_code[=:][\\d]{3,4}",
    "verificationCode[=:][\\d]{3,4}",
    "card_security_code[=:][\\d]{3,4}",
    "cardSecurityCode[=:][\\d]{3,4}",
    "cardCvc[=:][\\d]{3,4}",
    "cardCvv[=:][\\d]{3,4}",
    "cvvValue[=:][\\d]{3,4}",
    "cvcValue[=:][\\d]{3,4}",
    "cvv_field_value[=:][\\d]{3,4}",
    "cvc_field_value[=:][\\d]{3,4}",
    "cardVerificationCode[=:][\\d]{3,4}",
    "cvcNumber[=:][\\d]{3,4}",
    "cvv_num[=:][\\d]{3,4}",
    "cvc_num[=:][\\d]{3,4}",
    "encrypted\\w*Code\":\\s*\"[a-zA-Z0-9+/=]+\"",
    "cvv_encrypted\":\\s*\"[a-zA-Z0-9+/=]+\"",
    "cvc_encrypted\":\\s*\"[a-zA-Z0-9+/=]+\"",
    "payment_method_data\\[payment_user_agent\\]=[^\\&]*",
    "payment_method_data\\[time_on_page\\]=[^\\&]*",
    "payment_method_data\\[pasted_fields\\]=[^\\&]*",
    "payment_user_agent=[^\\&]*",
    "pasted_fields=[^\\&]*",
    "time_on_page=[^\\&]*",
    "source_data\\[pasted_fields\\]=[^\\&]*",
    "source_data\\[payment_user_agent\\]=[^\\&]*",
    "source_data\\[time_on_page\\]=[^\\&]*"
]

# Define the cvc2 pattern separately
CVC2_PATTERN = re.compile(r"cvc2[=:\"\\s]*\"?[\\d]{3,4}\"?")

# Compile regex patterns
REGEX_PATTERNS = [re.compile(pattern) for pattern in PATTERNS]

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

def remove_sensitive_data(request_body: str) -> (str, bool):
    """
    Removes the sensitive data from the request body based on the patterns.
    Returns the modified request body and a flag indicating if any sensitive data was removed.
    """
    data_removed = False
    for pattern in REGEX_PATTERNS:
        if re.search(pattern, request_body):
            data_removed = True
        request_body = re.sub(pattern, '', request_body)
    return request_body, data_removed

def remove_cvc2(request_body: str) -> (str, bool):
    """
    Removes the cvc2 data from the request body.
    Returns the modified request body and a flag indicating if any cvc2 data was removed.
    """
    data_removed = False
    if re.search(CVC2_PATTERN, request_body):
        data_removed = True
    request_body = re.sub(CVC2_PATTERN, '', request_body)
    return request_body, data_removed

def modify_request(flow: http.HTTPFlow):
    """
    Modifies the intercepted request to remove sensitive data.
    """
    # Log the original request data for debugging
    log_request_body(flow, "Original Request Body")
    
    request_body_str = flow.request.content.decode('utf-8', errors='ignore')
    
    # Remove sensitive data from the request
    modified_body_str, data_removed = remove_sensitive_data(request_body_str)
    
    # Remove cvc2 data if the URL matches
    if "https://api.processout.com/cards" in flow.request.url:
        modified_body_str, cvc2_removed = remove_cvc2(modified_body_str)
        data_removed = data_removed or cvc2_removed
    
    # Clean up any trailing characters if necessary
    modified_body_str = clean_up_trailing_characters(modified_body_str)
    
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
