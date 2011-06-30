#! /usr/bin/env python
"""
    Perfrom cluster reconnaissance
"""


from eventlet.green import urllib2
from swift.common.ring import Ring
import simplejson as json
from hashlib import md5
import datetime
import eventlet
import optparse
import os

VERBOSE = False


def getdevices():
    ring_file = "/etc/swift/object.ring.gz"
    ring_data = Ring(ring_file)
    ips = set((n['ip'], n['port']) for n in ring_data.devs)
    return ips


def scout(base_url, recon_type):
    global VERBOSE
    url = base_url + recon_type
    try:
        body = urllib2.urlopen(url).read()
        content = json.loads(body)
        if VERBOSE:
            print "-> %s: %s" % (url, content)
        status = 200
    except urllib2.HTTPError as e:
        print "-> %s: %s" % (url, e)
        content = e
        status = e.code
    except urllib2.URLError as e:
        print "-> %s: %s" % (url, e)
        content = e
        status = -1
    return url, content, status


def scout_md5(host):
    global VERBOSE
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "ringmd5")
    return url, content, status


def scout_async(host):
    global VERBOSE, ASYNC_COUNTER
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "async")
    return url, content, status


def get_ringmd5(ringfile):
    stats = {}
    hosts = getdevices()
    md5sum = md5()
    with open(ringfile, 'rb') as f:
        block = f.read(4096)
        while block:
            md5sum.update(block)
            block = f.read(4096)
    ring_sum = md5sum.hexdigest()
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Checking ring md5sum's on %s hosts..." % (now, len(hosts))
    if VERBOSE:
        print "-> On disk md5sum: %s" % ring_sum
    for url, response, status in pool.imap(scout_md5, hosts):
        if status == 200:
            #fixme - need to grab from config
            stats[url] = response[ringfile]
            if response[ringfile] != ring_sum:
                print "!! %s (%s) doesn't match on disk md5sum" % (url,
                    response[ringfile])
            else:
                if VERBOSE:
                    print "-> %s matches." % url
    print "=" * 79


def async_check():
    ASYNC_COUNTER = 0
    stats = {}
    hosts = getdevices()
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Checking async pendings on %s hosts..." % (now, len(hosts))
    for url, response, status in pool.imap(scout_async, hosts):
        if status == 200:
            stats[url] = response['async_pending']
    if len(stats) > 0:
        low = min(stats.values())
        high = max(stats.values())
        total = sum(stats.values())
        average = total / len(stats)
        print "Async stats: low: %d, high: %d, avg: %d, total: %d" % (low,
            high, average, total)
        print "=" * 79
    else:
        print "Error: No hosts where available or returned valid information."


def main():
    global VERBOSE, swift_dir, pool
    print "=" * 79
    usage = '''
    usage: %prog [-v] [-a] [-r] [-u] [-d] [-l] [-c] [--objmd5]
    '''
    args = optparse.OptionParser(usage)
    args.add_option('--verbose', '-v', action="store_true",
        help="Print verbose info")
    args.add_option('--async', '-a', action="store_true",
        help="Get async stats")
    args.add_option('--replication', '-r', action="store_true",
        help="Get replication stats")
    args.add_option('--unmounted', '-u', action="store_true",
        help="Check cluster for unmounted devices")
    args.add_option('--diskusage', '-d', action="store_true",
        help="Get disk usage stats")
    args.add_option('--loadstats', '-l', action="store_true",
        help="Get cluster load average stats")
    args.add_option('--connstats', '-c', action="store_true",
        help="Get connection stats")
    args.add_option('--objmd5', action="store_true",
        help="Get md5sums of object.ring.gz and compare to local copy")
    args.add_option('--swiftdir', default="/etc/swift",
        help="Default = /etc/swift")
    options, arguments = args.parse_args()

    swift_dir = options.swiftdir

    if options.verbose is True:
        VERBOSE = True
    if options.async is True:
        async_check()
    if options.replication is True:
        replication_check()
    if options.objmd5:
        get_ringmd5(os.path.join(swift_dir, 'container.ring.gz'))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print '\n'
