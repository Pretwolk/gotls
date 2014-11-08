#!/usr/bin/env python3.4

import pickle
import pprint
import sys
import ipaddress

nxdomain = []
supportstls = []
notsupportstls = []
totalservers = []
verifiedchain = []
notverifiedchain = []
heartbleed = []
vulnerablekey = []
SupportedTLSProtocols = {}
keysize = {}


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
  
  sys.exit()

unknownStartTLS = []
for domain,ddata in data.items():
  if isinstance(ddata,dict):
    for addr, daddr in sorted(ddata.items()):
      if not get_ip_version(addr):
        break

      if daddr["SupportsTLS"]:
        if addr not in supportstls:
          supportstls.append(addr)
      elif daddr["SupportsTLS"] == None:
        if addr not in unknownStartTLS:
          unknownStartTLS.append(addr)
      elif not daddr["SupportsTLS"]:
        if addr not in notsupportstls:
          notsupportstls.append(addr)

      if "SupportsTLS" in daddr and daddr["SupportsTLS"] and addr not in supportstls:
        supportstls.append(addr)
      elif "SupportsTLS" in daddr and not daddr["SupportsTLS"] and addr not in notsupportstls:
        notsupportstls.append(addr)


      if "VerifiedChain" in daddr:
        for mx,d in daddr["VerifiedChain"].items():
          if d and mx:
            if d[0] and mx not in verifiedchain:
              verifiedchain.append(mx)
            if not d[0] and mx not in notverifiedchain:
              notverifiedchain.append(addr)
      
      if "SupportedTLSProtocols" in daddr and daddr["SupportsTLS"]:
        for proto in daddr["SupportedTLSProtocols"]:
          if proto not in SupportedTLSProtocols:
            SupportedTLSProtocols[proto] = []
          if addr not in SupportedTLSProtocols:
            SupportedTLSProtocols[proto].append(addr)
      
      if "keysize" in daddr:
        if daddr["keysize"] not in keysize:
          keysize[daddr["keysize"]] = 0
        keysize[daddr["keysize"]] = keysize[daddr["keysize"]] + 1

      if "vulnerablekey" in daddr:
        if addr not in vulnerablekey:
          vulnerablekey.append(addr)

  else:
    nxdomain.append(domain)

totalservers = int(len(supportstls)) + int(len(notsupportstls)) + int(len(unknownStartTLS))
#pprint.pprint(data)

#print("Domain not found, " + str(len(nxdomain)))
print("totalservers, " + str(totalservers))
print("SupportsTLS, " + str(len(supportstls)))
print("notSupportsTLS, " + str(len(notsupportstls)))
print("unknownStartTLS, " + str(len(unknownStartTLS)))
#print("verifiedchain, " + str(len(verifiedchain)))
#print("notverifiedchain, " + str(len(notverifiedchain)))
#print("vulnerablekey, " + str(len(vulnerablekey)))
#for k,v in keysize.items():
#  print("Keysize",str(k)+" "+str(v))
for k,v in sorted(SupportedTLSProtocols.items()):
  print("SupportedTLSProtocols",str(k)+" "+str(len(v)))
