#! /usr/bin/env python
#coding:utf-8

from hashlib import md5
import urllib
import sys
import time
from urlparse import urlparse, parse_qs
import traceback
import uuid
import base64

def to_deadline(rang):
    return int(time.time()) + rang

def t16(t):
    return hex(t)[2:].lower()   # 16 进制小写形式

def summd5(str):
    m = md5()
    m.update(str)
    return m.hexdigest()


def sign(key, t, path):
    sign_s = summd5(key + path + t).lower()
    sign_part = "sign=" + sign_s + "&t=" + t
    return sign_part

# p_url 不包含查询参数部分，带 scheme
# p_query 不含问号 "?"
def sign_url(key, t, p_url, p_query=""):
    url = urllib.quote(p_url.decode(sys.stdin.encoding).encode("utf8"), safe="-_.!~*'();/:@&=+$,")
    up = urlparse(url)
    path = up.path
    sign_part = sign(key, t, path)
    if p_query:
        query_part = "?" + p_query + "&"+ sign_part
    else:
        query_part = "?" + sign_part

    return up.scheme + "://" + up.netloc + path + query_part


# example:
# url = "http://signt.qnssl.com/Dir1:2 3-_.!~*'();/?:@&=+$,#/视屏/音yue/test1234.mp4"
# p_url 不包含查询参数部分，带 scheme
# p_query 不含 ?
# signed_url = sign_url(key, t, url, "v=2")


def signt_help():
    print
    print "signt time <key> <url> <t>"
    print "signt deadline <key> <url> <deadline>"
    print "signt expires <key> <url> <expires>"
    print "signt check <key> <signed_url>"
    print "signt show <t>"
    print "signt genkey"
    print


def sign_time(key, url, rang):
    print("range: " + str(rang))
    deadline = to_deadline(rang)
    sign_deadline(key, url, deadline)

def sign_deadline(key, url, deadline):
    print
    print("key: " + key)
    print("url: " + url)
    print("      url 不要包含查询参数。若有查询参数，将其直接插入到 ‘生成好的url’ 的 ‘签名’参数前")
    print("deadline: " + t16(deadline) + ", " + str(deadline) + ", " + time.ctime(deadline))
    print
    t = t16(deadline)
    signed_url = sign_url(key, t, url)
    print signed_url
    print

def sign_expires(key, url, expires):
    print
    print("key: " + key)
    print("url: " + url)
    print("      url 不要包含查询参数。若有查询参数，将其直接插入到 ‘生成好的url’ 的 ‘签名’参数前")
    print("deadline: " + t16(to_deadline(expires)) + ", " + str(to_deadline(expires)) + ", " + time.ctime(to_deadline(expires)))
    print
    t = t16(to_deadline(expires))
    signed_url = sign_url(key, t, url)
    print signed_url
    print

def sign_check(key, signed_url):
    url = urllib.quote(signed_url.decode(sys.stdin.encoding).encode("utf8"), safe="-_.!~*'();/:@&=+$,?")
    u = urlparse(url)
    t = parse_qs(u.query)["t"][0]
    sign_s = summd5(key + u.path + t).lower()
    print
    print("deadline: " + str(int(t, 16)) + " , " + time.ctime(int(t, 16)))
    print(sign_s)
    print(parse_qs(u.query)["sign"][0] == sign_s)
    print

def show_t(t):
    i_t = int(t, 16)
    s_t = time.ctime(i_t)
    print
    print(t + " : " + str(i_t) + " : " + s_t)
    print

def gen_key():
    print
    print base64.urlsafe_b64encode(str(uuid.uuid4()))[:40]
    print

try:
    type = sys.argv[1]

    if type == "time":
        sign_time(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif type == "deadline":
        sign_deadline(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif type == "expires":
        sign_expires(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif type == "check":
        sign_check(sys.argv[2], sys.argv[3])
    elif type == "show":
        show_t(sys.argv[2])
    elif type == "genkey":
        gen_key()
    else:
        signt_help()
except Exception as e:
    # print traceback.format_exc()
    signt_help()
