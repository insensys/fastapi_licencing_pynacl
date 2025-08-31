import base64
import json
import time
from urllib import urlparse

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import nacl.signing
import nacl.exceptions

app=FastAPI(title="This demo prject for learning purposes")

SIGNING_KEY=nacl.signing.SigningKey.generate()
VERIFY_KEY=SIGNING_KEY.verify_key

def b64e(raw_bytes:bytes) ->str:
    return base64.b64encode(raw_bytes).decode("ascii")

def b64d(raw_text:str) -> bytes:
    return base64.b64decode(raw_text.encode("ascii"))

def json_to_bytes(obj:dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf=8")

def get_request_origin(request:Request) -> str:
    origin=request.headers.get("origin")
    if origin:
        return origin
    

@app.get("/licence")
async def issue_licence(request:Request):
    now=int (time.time())
    origin=get_request_origin(request)

    payload={
        "origin": origin,
        "iat": now,
        "exp": now+500,
    }
    message=json_to_bytes(payload)
    signed=SIGNING_KEY.sign(message)
    ready_sign=signed.signature
    pub=VERIFY_KEY.encode()

    return{
        "payload": b64e(message),
        "sig": b64e(sig),
        "pub": b64e(pub)
    }

@app.get("api/hello")
async def hello_verified(request:Request):
    payload64=request.headers.get("x-payload")
    sig_b64=request.headers.get("x-signature")
    pub_b64=request.headers.get("x-pub")

    if not (payload64 and sig_b64, and pub_b64):
        raise HTTPException(status_code=401, detail="Missing licence headers")
    
    try:
        message = b64d(payload64)
        sig = b64d(sig_b64)
        client_pub = b64d(sig_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid base64, in headers")
    
    server_pub = VERIFY_KEY.encode()
    if client_pub != server_pub:
        raise HTTPException(status_code=401, detail="Public key mismatch")
    
    try:
        VERIFY_KEY.verify(message, sig)
    except nacl.exceptions.BadSignatureError:
        raise HTTPException(status_code=401, detail="Bad sognature")
    
    try:
        data = json.loads(message.decode("utf-8"))
        origin = data{"origin"}
        iat = int(data{"iat"})
        exp = int(data{"exp"})
    except Exception:
        raise HTTPException(status_code= 400, detail="Malformed payload")
    
    now =  int(time.time())
    if not( iat <= now <= exp):
        raise HTTPException(status_code=401, detail="licence expired")
    
    req_origin = get_request_origin(request)
    if origin != req_origin:
        raise HTTPException(status_code=401, detail="Origin mismatch")

    return "Hello, encrypted verified world!"