"""Leaf and spine topology for use with ONOS segment routing application:

Create a leaf an spine topology, posting configuration to ONOS controller,
while configuring sFlow monitoring and posting topology to sFlow-RT:

sudo env ONOS=10.0.0.73 mn --custom sr.py,sflow-rt/extras/sflow.py \
--link tc,bw=10 --topo=sr '--controller=remote,ip=$ONOS,port=6653'

"""

from mininet.topo import Topo
from mininet.node import Host
from requests import post
from json import dumps
from os import environ

class IpHost(Host):
  def __init__(self, name, gateway, *args, **kwargs):
    super(IpHost, self).__init__(name, *args, **kwargs)
    self.gateway = gateway

  def config(self, **kwargs):
    Host.config(self, **kwargs)
    mtu = "ifconfig "+self.name+"-eth0 mtu 1490"
    self.cmd(mtu)
    self.cmd('ip route add default via %s' % self.gateway)

class LeafSpine( Topo ):

  def __init__( self, spine, leaf, host ):

    Topo.__init__( self )

    netcfg = {"ports":{},"devices":{}, "hosts": {}, "links": {}}
    hostcfg = {}

    spines = {}

    for s in range(spine):
      sid = s+1
      name = 'spine%s' % (s+1)
      ip = '192.168.0.%s' % sid
      mac = '00:00:00:00:00:%s' % format(sid,'02x')
      dpid = format(sid,'016x')
      netcfg["devices"]["of:%s" % dpid] = {
        "segmentrouting":{
          "ipv4NodeSid":sid,
          "ipv4Loopback":ip,
          "routerMac":mac,
          "isEdgeRouter":False,
          "adjacencySids":[]
        },
        "basic":{
          "name":name,
          "driver":"ofdpa-ovs"
        }
      }
      
      spines[s] = self.addSwitch(name, dpid=dpid)

    for l in range(leaf):
      sid = spine + l + 1
      name = 'leaf%s' % (l+1)
      ip = '192.168.0.%s' % sid
      mac = '00:00:00:00:00:%s' % format(sid,'02x')
      dpid = format(sid,'016x')
      netcfg["devices"]["of:%s" % dpid] = {
        "segmentrouting":{
          "ipv4NodeSid":sid,
          "ipv4Loopback":ip,
          "routerMac":mac,
          "isEdgeRouter":True,
          "adjacencySids":[]
        },
        "basic":{
          "name":name,
          "driver":"ofdpa-ovs"
        }
      }

      leafSwitch = self.addSwitch(name, dpid=dpid)

      for s in range(spine):
        spineSwitch = spines[s]
        netcfg["links"]["%s/%s-%s/%s" % (dpid,s+1,format(s+1,'016x'),l+1)] = {
          "basic": {}
        }
        netcfg["links"]["%s/%s-%s/%s" % (format(s+1,'016x'),l+1,dpid,s+1)] = {
          "basic": {}
        }

        self.addLink(leafSwitch,spineSwitch,port1=s+1,port2=l+1)

      for h in range(host):
        hid = (l*host)+h+1
        name = 'h%s' % hid
        ip = '10.1.%s.%s' % (l+1, h+1)
        cidr = '%s/24' % ip
        router = '10.1.%s.254' % (l+1)
        mac = '00:00:00:00:01:%s' % format(hid,'02x')
        port = spine + h + 1
        location = "of:%s/%s" % (dpid, port)

        netcfg["hosts"]["%s/-1" % mac] = {
          "basic": {
             "ips": [ ip ],
             "locations": [ location ]
          }
        }

        endHost = self.addHost(name, cls=IpHost, mac=mac, ip=cidr, gateway=router)

        netcfg["ports"][location] = {
          "interfaces": [
            {
              "ips":["%s/24" % router],
              "vlan-untagged":1
            }
          ]
        }

        self.addLink(leafSwitch,endHost,port1=port)           

    onos = environ.get('ONOS','127.0.0.1')
    post('http://'+onos+':8181/onos/v1/network/configuration/', auth=('onos','rocks'), json=netcfg).text

topos = { 'sr': ( lambda spine=2,leaf=2,host=2: LeafSpine(int(spine),int(leaf),int(host)) ) }
