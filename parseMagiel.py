#!/usr/bin/env python3.4

import pickle
import pprint
import sys
import ipaddress

nxdomain = []
supportstls = []
notsupportstls = []
unknownStartTLS = []
totalservers = []
verifiedchain = []
notverifiedchain = []
heartbleed = []
vulnerablekey = []
SupportedTLSProtocols = {}
keysize = {}
protos = ["SSLv3","TLSv1","TLSv1.1","TLSv1.2"]

def get_ip_version(address):
  try:
    if 4 == ipaddress.IPv4Address(address).version:
      return int(4)
  except:
    pass
  try:
    if 6 == ipaddress.IPv6Address(address).version:
      return int(6)
  except:
    pass
  return False


try: 
  with open("results","rb") as file:
    data = pickle.load(file)
except:
  print("ERROR LOADING FILE")  

for domain,ddata in data.items():
  if ddata != "NXDOMAIN" and type(ddata) == dict:
    for addr,daddr in sorted(ddata.items()):
      if get_ip_version(addr):

        if "SupportedTLSProtocols" in daddr and daddr["SupportsTLS"] and type(daddr["SupportedTLSProtocols"]) == list:          
          for proto in sorted(daddr["SupportedTLSProtocols"]):
            if proto in protos and proto not in SupportedTLSProtocols:
              SupportedTLSProtocols[proto] = []
            if proto in protos and addr not in SupportedTLSProtocols:
              SupportedTLSProtocols[proto].append(addr)

        if daddr["SupportsTLS"]:
          if addr not in supportstls:
            supportstls.append(addr)

        elif daddr["SupportsTLS"] == None: 
          if addr not in unknownStartTLS:
            unknownStartTLS.append(addr)

        elif not daddr["SupportsTLS"]:
          if addr not in notsupportstls:
            notsupportstls.append(addr)
        
        if "VerifiedChain" in daddr:
          for mx,d in daddr["VerifiedChain"].items():
            if type(d) == tuple:  
              if d[0]:
                if mx not in verifiedchain:
                  verifiedchain.append(mx)
              if not d[0]:
                if mx not in notverifiedchain:
                  notverifiedchain.append(mx)
                  #print(d[1])

        if "vulnerablekey" in daddr:
          if addr not in vulnerablekey:
            vulnerablekey.append(addr)

        if "cert" in daddr:
          hash = daddr["cert"]
          if hash in ddata["_certs"]:
            ks = ddata["_certs"][hash]["keysize"]
  
            if str(ks) not in keysize:
              keysize[str(ks)] = []
            if addr not in keysize:
              keysize[str(ks)].append(addr)
          else:
            print(hash,"cert not found")
        

        if "heartbleed" in daddr:
          if addr not in heartbleed:
            heartbleed.append(addr)

#print("Domain not found, " + str(len(nxdomain)))
totalservers = int(len(supportstls)) + int(len(notsupportstls)) + int(len(unknownStartTLS))
print("totalservers, " + str(totalservers))
print("SupportsTLS, " + str(len(supportstls)))
print("notSupportsTLS, " + str(len(notsupportstls)))
print("unknownStartTLS, " + str(len(unknownStartTLS)))
print("verifiedchain, " + str(len(verifiedchain)))
print("notverifiedchain, " + str(len(notverifiedchain)))
#print("vulnerablekey, " + str(len(vulnerablekey)))
print("heartbleed, " + str(len(heartbleed)))
for k,v in sorted(keysize.items()):
  print("Keysize",str(k)+" "+str(len(v)))
for k,v in sorted(SupportedTLSProtocols.items()):
  print("SupportedTLSProtocols",str(k)+" "+str(len(v)))


sys.exit()

for domain,ddata in data.items():
  if isinstance(ddata,dict):
    for addr, daddr in ddata.items():
      if not get_ip_version(addr):
#        print(addr,"not an IP address!")
        break

      if addr not in totalservers:
        totalservers.append(addr)

      if "SupportsTLS" in daddr and daddr["SupportsTLS"] and addr not in supportstls:
        supportstls.append(addr)
      if "SupportsTLS" in daddr and not daddr["SupportsTLS"] and addr not in notsupportstls:
        notsupportstls.append(addr)

      if "VerifiedChain" in daddr:
        for mx,d in daddr["VerifiedChain"].items():

          if d and mx:

            if d[0] and mx not in verifiedchain:
              verifiedchain.append(mx)

            if not d[0] and mx not in notverifiedchain:
              notverifiedchain.append(addr)
      
      if "heartbleed" in daddr:
        if addr not in heartbleed:
          heartbleed.append(addr)

      if "SupportedTLSProtocols" in daddr and daddr["SupportsTLS"]:
        for proto in daddr["SupportedTLSProtocols"]:
          if proto not in SupportedTLSProtocols:
            SupportedTLSProtocols[proto] = []
          if addr not in SupportedTLSProtocols:
            SupportedTLSProtocols[proto].append(addr)
      
      if "vulnerablekey" in daddr:
        if addr not in vulnerablekey:
          vulnerablekey.append(addr)

  else:
    nxdomain.append(domain)

#pprint.pprint(data)

