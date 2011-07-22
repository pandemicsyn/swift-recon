#! /usr/bin/env python
"""
    cmdline utility to perfrom cluster reconnaissance
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
SUPPRESS_ERRORS = False


def getdevices():
    #todo , fitler by zone[s]
    ring_file = "/etc/swift/object.ring.gz"
    ring_data = Ring(ring_file)
    for n in ring_data.devs:
        print n['ip'], n['port'], n['zone']
    ips = set((n['ip'], n['port']) for n in ring_data.devs)
    return ips


def scout(base_url, recon_type):
    global VERBOSE, SUPPRESS_ERRORS
    url = base_url + recon_type
    try:
        body = urllib2.urlopen(url).read()
        content = json.loads(body)
        if VERBOSE:
            print "-> %s: %s" % (url, content)
        status = 200
    except urllib2.HTTPError as e:
        if not SUPPRESS_ERRORS or VERBOSE:
            print "-> %s: %s" % (url, e)
        content = e
        status = e.code
    except urllib2.URLError as e:
        if not SUPPRESS_ERRORS or VERBOSE:
            print "-> %s: %s" % (url, e)
        content = e
        status = -1
    return url, content, status


def scout_md5(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "ringmd5")
    return url, content, status


def scout_async(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "async")
    return url, content, status


def scout_replication(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "replication")
    return url, content, status


def scout_load(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "load")
    return url, content, status


def scout_du(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "diskusage")
    return url, content, status


def scout_umount(host):
    base_url = "http://%s:%s/recon/" % (host[0], host[1])
    url, content, status = scout(base_url, "unmounted")
    return url, content, status


def get_ringmd5(ringfile):
    stats = {}
    matches = 0
    errors = 0
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
                ringsmatch = False
                print "!! %s (%s) doesn't match on disk md5sum" % \
                    (url, response[ringfile])
            else:
                matches = matches + 1
                if VERBOSE:
                    print "-> %s matches." % url
        else:
            errors = errors + 1
    print "%s/%s hosts matched, %s error[s] while checking hosts." % \
            (matches, len(hosts), errors)
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
    else:
        print "Error: No hosts where available or returned valid information."
    print "=" * 79


def umount_check():
    ASYNC_COUNTER = 0
    stats = {}
    hosts = getdevices()
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Getting unmounted drives from %s hosts..." % (now, len(hosts))
    for url, response, status in pool.imap(scout_umount, hosts):
        if status == 200:
            for i in response:
                stats[url] = i['device']
    for host in stats:
        print "Not mounted: %s on %s" % (stats[host], host)
    print "=" * 79


def replication_check():
    stats = {}
    hosts = getdevices()
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Checking replication times on %s hosts..." % (now, len(hosts))
    for url, response, status in pool.imap(scout_replication, hosts):
        if status == 200:
            stats[url] = response['object_replication_time']
    if len(stats) > 0:
        low = min(stats.values())
        high = max(stats.values())
        total = sum(stats.values())
        average = total / len(stats)
        print "[Replication Times] shortest: %s, longest: %s, avg: %s" % \
            (low, high, average)
    else:
        print "Error: No hosts where available or returned valid information."
    print "=" * 79


def load_check():
    load1 = {}
    load5 = {}
    load15 = {}
    hosts = getdevices()
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Checking load avg's on %s hosts..." % (now, len(hosts))
    for url, response, status in pool.imap(scout_load, hosts):
        if status == 200:
            load1[url] = response['1m']
            load5[url] = response['5m']
            load15[url] = response['15m']
    stats = {"1m": load1, "5m": load5, "15m": load15}
    for item in stats:
        if len(stats[item]) > 0:
            low = min(stats[item].values())
            high = max(stats[item].values())
            total = sum(stats[item].values())
            average = total / len(stats[item])
            print "[%s load average] lowest: %s, highest: %s, avg: %s" % \
                (item, low, high, average)
        else:
            print "Error: Hosts unavailable or returned valid information."
    print "=" * 79


def disk_usage():
    hosts = getdevices()
    stats = {}
    highs = []
    lows = []
    averages = []
    percents = {}
    pool = eventlet.GreenPool(20)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print "[%s] Checking disk usage on %s hosts..." % (now, len(hosts))
    for url, response, status in pool.imap(scout_du, hosts):
        if status == 200:
            hostusage = []
            for entry in response:
                if entry['mounted']:
                    used = float(entry['used']) / float(entry['size']) * 100.0
                    hostusage.append(round(used, 2))
            stats[url] = hostusage

    for url in stats:
        if len(stats[url]) > 0:
            #get per host hi/los for another day
            low = min(stats[url])
            high = max(stats[url])
            total = sum(stats[url])
            average = total / len(stats[url])
            highs.append(high)
            lows.append(low)
            averages.append(average)
            for percent in stats[url]:
                percents[percent] = percents.get(percent, 0) + 1
    else:
            print "-> %s: Error. No drive info available." % url

    if len(lows) > 0:
        low = min(lows)
        high = max(highs)
        average = sum(averages) / len(averages)
        #distrib graph shamelessly stolen from https://github.com/gholt/tcod
        print "Distribution Graph:"
        mul = 69.0 / max(percents.values())
        for percent in sorted(percents):
            print '% 3d%% % 4d %s' % (percent, percents[percent], \
                '*' * int(percents[percent] * mul))

        print "Disk usage: lowest: %s%%, highest: %s%%, avg: %s%%" % \
            (low, high, average)
    else:
        print "Error: No hosts where available or returned valid information."
    print "=" * 79


def main():
    global VERBOSE, SUPPRESS_ERRORS, swift_dir, pool
    print "=" * 79
    usage = '''
    usage: %prog [-v] [--suppress] [-a] [-r] [-u] [-d] [-l] [-c] [--objmd5]
    '''
    args = optparse.OptionParser(usage)
    args.add_option('--verbose', '-v', action="store_true",
        help="Print verbose info")
    args.add_option('--suppress', action="store_true",
        help="Suppress most connection related errors")
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

    VERBOSE = options.verbose
    SUPPRESS_ERRORS = options.suppress

    if options.async:
        async_check()
    if options.unmounted:
        umount_check()
    if options.replication:
        replication_check()
    if options.loadstats:
        load_check()
    if options.diskusage:
        disk_usage()
    if options.objmd5:
        get_ringmd5(os.path.join(swift_dir, 'object.ring.gz'))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print '\n'
