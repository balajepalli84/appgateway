
import io
import json
import hashlib
import hmac
import base64
from datetime import datetime, timezone
import re
from fdk import response

def calculate_sha256(input_string):
    input_bytes = input_string.encode()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_bytes)
    hex_digest = sha256_hash.hexdigest()
    return hex_digest

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def extract_signature(auth_string):
    pattern = r"Signature=([a-fA-F0-9]+)"
    match = re.search(pattern, auth_string)
    if match:
        return match.group(1)
    else:
        return None

def handler(ctx, data: io.BytesIO=None):
    req_vars = json.loads(data.getvalue())
    json_string=json.dumps(req_vars)
    print(f"API GW data is {json_string}", flush=True)
    secret_key = "="
    date_stamp = req_vars['data']['x-amz-date'].split('T')[0]
    region_name = req_vars['data']['host'].split('.')[2]
    service_name = 's3'
    method='PUT'
    src_signature = extract_signature(req_vars['data']['Authorization'])
    print(f"src_signature is {src_signature}", flush=True)
    #Create canonocial request
    input_string = (
        f"{method}\n"
        f"/{req_vars['data']['path']}\n"
        "\n"
        f"content-md5:{req_vars['data']['content-md5']}\n"
        f"host:{req_vars['data']['host']}\n"
        f"x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
        f"x-amz-date:{req_vars['data']['x-amz-date']}\n"
        "\n"
        "content-md5;host;x-amz-content-sha256;x-amz-date\n"
        f"UNSIGNED-PAYLOAD"
        )  

    print(f"input_string is {input_string}", flush=True)

    hash_result = calculate_sha256(input_string)    
    print(f"hash_result of input_string is {hash_result}", flush=True)

    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{req_vars['data']['x-amz-date']}\n"
        f"{date_stamp}/{region_name}/{service_name}/aws4_request\n"
        f"{hash_result}"
    )
    print(f"string_to_sign is {string_to_sign}", flush=True)

    signing_key = getSignatureKey(secret_key, date_stamp, region_name, service_name)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    print(f"signature is {signature}", flush=True)
    
    if src_signature == signature:
        print(f"signature is Valid", flush=True)
        return response.Response(
            ctx,
            response_data=json.dumps(
                            {
                                "active": True,
                                "context": {"TOKEN": "oauth2_csp_token"},
                            }
                        ),
            status_code = 200,
            headers={"Content-Type": "application/json"}
            )
    else:
        print(f"signature is In-Valid", flush=True)
        return response.Response(
            ctx,
            response_data=json.dumps(
                            {"message": "Failed to Validate the signature"}
                            ),
            status_code = 401,
            headers={"Content-Type": "application/json"}
            )
        

