import json, yaml
import urllib, urllib2
import time
from pymongo import MongoClient

def sendRequest(resource, apikey):
    '''checks to see if vt finished the scan'''
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"resource": resource, "apikey": apikey}
    data = urllib.urlencode(params)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    json = yaml.safe_load(json)
    return json

def configParse():
    '''parses the config file, vt.json'''
    with open('vt.json', 'r') as confFile:
        return json.load(confFile)

def mongoGetQueue():
    '''gets scan_id of docs in queue collection'''
    # change db name later
    client = MongoClient()
    db = client.vt
    queueDocs = db.queue.find()
    currentQueue = [str(doc['scan_id']) for doc in queueDocs]
    return currentQueue

def mongoQueueRemove(doc):
    '''removes document from queue, adds it to done collection'''
    # change db name later
    client = MongoClient()
    db = client.vt
    db.done.insert_one(doc)
    db.queue.delete_many({'scan_id' : doc['scan_id']})

def main():
    #read config
    try:
        conf = configParse()
    except IOError:
        print 'vt.json configuration file not found'
        sys.exit()
    apikey = str(conf['apikey'])
    wait = str(conf['wait'])

    while True:
        scanIds = mongoGetQueue()
        print len(scanIds), 'objects in queue'
        for id in scanIds:
            print 'Looking up', id, '...\n'
            req = sendRequest(id, apikey)
            if req:
                print req['verbose_msg'], '\n'
                if req['response_code'] == 1:
                    print 'sha256:', req['sha256']
                    print req['positives'], 'Positives /', req['total'], 'Total\n'
                    print 'Moving to done collection...\n'
                    mongoQueueRemove(req)
        print 'Waiting', int(wait), 'seconds for next request...\n'
        time.sleep(int(wait))
        print 'Checking DB for new entries...\n'

if __name__ == "__main__":
    main()

'''notes:
mongo - db name, table name
install script
mongodb user, security
vt user
change db name

db design
queue col
done col
'''