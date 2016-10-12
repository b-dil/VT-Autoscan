import httplib
import mimetypes
import sys
import json, yaml
from pymongo import MongoClient

def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTPS(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def sendFile(filename, apikey):
    '''sends file to vt'''
    host = 'www.virustotal.com'
    selector = 'https://www.virustotal.com/vtapi/v2/file/scan'
    apiKey = [('apikey', apikey)]
    openFile = open(filename, 'rb').read()
    files = [('file', filename, openFile)]
    json = post_multipart(host, selector, apiKey, files)
    return json 

def configParse():
    '''parses the config file, vt.json'''
    with open('vt.json', 'r') as confFile:
        return json.load(confFile)

def mongoInsert(doc):
    '''inserts document into mongodb'''
    # change db name later
    client = MongoClient()
    db = client.vt
    db.queue.insert_one(doc)
    
def main():
    #read config
    try:
        conf = configParse()
    except IOError:
        print 'vt.json configuration file not found'
        sys.exit()
    apikey = str(conf['apikey'])
    
    #send files
    f = sendFile(sys.argv[1], apikey)
    #yaml used because json loads as unicode, yaml loads as str and we're only using ascii
    fJson = yaml.safe_load(f)
    try:
        print fJson['verbose_msg']
        print 'sha256: ', fJson['sha256']
        print 'Scan ID: ', fJson['scan_id']
        print 'Link: ', fJson['permalink']
        mongoInsert(fJson)
    except TypeError:
        print 'Error, check your API key in vt.json'
        sys.exit()


if __name__ == "__main__":
    main()
