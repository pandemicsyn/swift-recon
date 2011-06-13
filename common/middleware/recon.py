# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from webob import Request, Response
#from swift.common.ring import Ring
from swift.common.utils import split_path, cache_from_env
from swift.common.constraints import check_mount
from os import statvfs, listdir
import simplejson as json


class ReconMiddleware(object):
    """
    Recon middleware used for monitoring.

    If the path is /recon/all|load|mem|async it will respond with system info.
    """

    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.devices = conf.get('devices', '/srv/node/')
        self.recon_cache_path = conf.get('recon_cache_path', \
            '/var/cache/swift')
        self.object_recon_cache = "%s/object.recon" % self.recon_cache_path
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              ('true', 't', '1', 'on', 'yes', 'y')

    def getmounted(self):
        """get ALL mounted fs from /proc/mounts"""
        mounts = []
        with open('/proc/mounts', 'r') as procmounts:
            for line in procmounts:
                mount = {}
                mount['device'], mount['path'], opt1, opt2, opt3, \
                    opt4 = line.rstrip().split()
                mounts.append(mount)
        return mounts

    def getload(self):
        """get info from /proc/loadavg"""
        loadavg = {}
        loadavg['1m'], loadavg['5m'], loadavg['15m'], loadavg['tasks'], \
            loadavg['processes'] \
                = open('/proc/loadavg', 'r').readline().rstrip().split()
        return loadavg

    def getmem(self):
        """get info from /proc/meminfo"""
        meminfo = {}
        with open('/proc/meminfo', 'r') as memlines:
            for i in memlines:
                entry = i.rstrip().split(":")
                meminfo[entry[0]] = entry[1].strip()
        return meminfo

    def getasyncinfo(self):
        """grab # of async pendings"""
        asyncinfo = {}
        with open(self.object_recon_cache, 'r') as f:
            recondata = json.load(f)
            if 'async_pending' in recondata:
                asyncinfo['async_pending'] = recondata['async_pending']
            else:
                asyncinfo['async_pending'] = -1
        return asyncinfo

    def getrepinfo(self):
        """grab last object replication time"""
        repinfo = {}
        with open(self.object_recon_cache, 'r') as f:
            recondata = json.load(f)
            if 'object_replication_time' in recondata:
                repinfo['object_replication_time'] = \
                    recondata['object_replication_time']
            else:
                repinfo['object_replication_time'] = -1
        return repinfo

    def getdeviceinfo(self):
        """place holder, grab dev info"""
        return self.devices

    def unmounted(self):
        """list unmounted (failed?) devices"""
        mountlist = []
        for entry in listdir(self.devices):
            mpoint = {'device': entry, \
                "mounted": check_mount(self.devices, entry)}
            if not mpoint['mounted']:
                mountlist.append(mpoint)
        return mountlist

    def diskusage(self):
        """get disk utilization statistics"""
        devices = []
        for entry in listdir(self.devices):
            if check_mount(self.devices, entry):
                path = "%s/%s" % (self.devices, entry)
                disk = statvfs(path)
                capacity = disk.f_bsize * disk.f_blocks
                available = disk.f_bsize * disk.f_bavail
                used = disk.f_bsize * (disk.f_blocks - disk.f_bavail)
                devices.append({'device': entry, 'mounted': True, \
                    'size': capacity, 'used': used, 'avail': available})
            else:
                devices.append({'device': entry, 'mounted': False, \
                    'size': '', 'used': '', 'avail': ''})
        return devices

    def ringverify(self):
        """place holder, verify ring info"""
        return "STUFF"

    def GET(self, req):
        error = False
        root, type = split_path(req.path, 1, 2, False)
        if type == "mem":
            content = json.dumps(self.getmem())
        elif type == "load":
            try:
                content = json.dumps(self.getload(), sort_keys=True)
            except IOError as e:
                error = True
                content = e
        elif type == "async":
            try:
                content = json.dumps(self.getasyncinfo())
            except (IOError, ValueError) as e:
                error = True
                content = e
        elif type == "replication":
            try:
                content = json.dumps(self.getrepinfo())
            except (IOError, ValueError) as e:
                error = True
                content = e
        elif type == "mounted":
            content = json.dumps(self.getmounted())
        elif type == "unmounted":
            content = json.dumps(self.unmounted())
        elif type == "diskusage":
            content = json.dumps(self.diskusage())
        elif type == "ringverify":
            content = json.dumps(self.ringverify())
        else:
            content = "Invalid path: %s" % req.path
            return Response(request=req, status="400 Bad Request", \
                body=content, content_type="text/plain")

        if not error:
            return Response(request=req, body=content, \
                content_type="application/json")
        else:
            return Response(request=req, status="500 Server Error", \
                body=content, content_type="text/plain")

    def __call__(self, env, start_response):
        req = Request(env)
        if req.path.startswith('/recon/'):
            return self.GET(req)(env, start_response)
        else:
            return self.app(env, start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def recon_filter(app):
        return ReconMiddleware(app, conf)
    return recon_filter
