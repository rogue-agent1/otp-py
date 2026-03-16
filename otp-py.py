#!/usr/bin/env python3
"""TOTP/HOTP one-time passwords (RFC 4226/6238)."""
import sys,struct,hashlib,time

def hmac_sha1(key,msg):
    bs=64
    if len(key)>bs:key=hashlib.sha1(key).digest()
    key=key.ljust(bs,b'\x00')
    return hashlib.sha1(bytes(k^0x5c for k in key)+hashlib.sha1(bytes(k^0x36 for k in key)+msg).digest()).digest()

def hotp(key,counter,digits=6):
    if isinstance(key,str):key=key.encode()
    msg=struct.pack('>Q',counter)
    h=hmac_sha1(key,msg)
    offset=h[-1]&0x0F
    code=struct.unpack('>I',h[offset:offset+4])[0]&0x7FFFFFFF
    return str(code%10**digits).zfill(digits)

def totp(key,period=30,digits=6,t=None):
    if t is None:t=int(time.time())
    counter=t//period
    return hotp(key,counter,digits)

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--test":
        key=b"12345678901234567890"
        # RFC 4226 test vectors
        expected=["755224","287082","359152","969429","338314","254676","287922","162583","399871","520489"]
        for i,exp in enumerate(expected):
            assert hotp(key,i)==exp,f"HOTP({i})={hotp(key,i)}, expected {exp}"
        # TOTP consistency
        t=1234567890
        code1=totp(key,t=t);code2=totp(key,t=t)
        assert code1==code2
        # Different time = different code (usually)
        code3=totp(key,t=t+30)
        # Just verify it returns 6 digits
        assert len(code3)==6 and code3.isdigit()
        print("All tests passed!")
    else:
        key=b"SUPERSECRETKEY!!"
        code=totp(key);remaining=30-int(time.time())%30
        print(f"TOTP: {code} ({remaining}s remaining)")
if __name__=="__main__":main()
