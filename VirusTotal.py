#!/usr/bin/python3
from __future__ import print_function
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from json2html import *
import imgkit
import hashlib

class VirusTotal:

  def init(self):
    config=None
    try:
      with open('config.json', 'r') as configFile:
        configContent = configFile.read()
        config=json.loads(configContent)
    except json.decoder.JSONDecodeError:
      print("Problem occured while parsing the config.json file")
      exit()
    if config==None:
      print("Problem occured while parsing the config.json file")
      exit()
    global OutputDir
    OutputDir = config['General']['OutputDir']
    global HTMLHeader
    HTMLHeader = config['General']['HTMLHeader']
    global TablesClass
    TablesClass = config['General']['TablesClass']
    global APIKeys
    APIKeys = config['VirusTotal']['APIKeys']
    self.loadRecordsTmp()
    global APIKey
    APIKEY = APIKeys[APIKeyIndex]
    global APIKeysNumber
    APIKeysNumber = len(APIKeys)
    global DisabledAttr
    DisabledAttr = config['VirusTotal']['DisabledAttr']
    global MaxResults
    MaxResults = config['VirusTotal']['MaxResults']
    global AttrSubstitution
    AttrSubstitution = config['VirusTotal']['AttrSubstitution']
    global Order
    Order = config['VirusTotal']['Order']
    global VTInstance
    VTInstance = VirusTotalPublicApi(APIKEY)
    self.HTML=""
    self.IMG=""

  def preHandling(self):
    self.number={}
    self.history={}

  def loadRecordsTmp(self):
    global APIKeyIndex
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
        APIKeyIndex=recordsTmp["APIKeyIndex"]
    except Exception:
      APIKeyIndex=0
      recordsTmp={"APIKeyIndex":APIKeyIndex}
      with open('.records.tmp', 'w') as recordsTmpFile:
        json.dump(recordsTmp, recordsTmpFile)

  def updateAPIKeyIndex(self):
    try:
      with open('.records.tmp', 'r') as recordsTmpFile:
        recordsTmpContent = recordsTmpFile.read()
        recordsTmp=json.loads(recordsTmpContent)
    except Exception:
      recordsTmp={"APIKeyIndex":APIKeyIndex}
    recordsTmp["APIKeyIndex"]=APIKeyIndex
    with open('.records.tmp', 'w') as recordsTmpFile:
      json.dump(recordsTmp, recordsTmpFile)

  def updateVTInstance(self):
    global APIKeyIndex
    APIKeyIndex=(APIKeyIndex+1)%APIKeysNumber
    self.updateAPIKeyIndex()
    global APIKEY
    APIKEY = APIKeys[APIKeyIndex]
    global VTInstance
    VTInstance = VirusTotalPublicApi(APIKEY)
    #print(APIKEY)

  def getIPReportAPI(self):
    result={}
    with open("input_ip.txt") as file:
      ips=file.read().strip()
      for ip in ips.split("\n"):
        response = VTInstance.get_ip_report(ip)
        self.updateVTInstance()
        if response['response_code']==200:
          result[ip]=response['results']
        #result.append(json.dumps(response, sort_keys=False, indent=4))
        #print(response)
    return result

  def formatArrayDateDomain(self,ip_report_api,attr):
      result=[]
      count=MaxResults[attr] if MaxResults[attr] else -1
      tmp=sorted(ip_report_api[attr], key=lambda i: i['last_resolved'])
      for elem in list(reversed(tmp)):
        if count==0:
          break
        obj={'Date resolved':"", 'Domain':""}
        obj['Date resolved']=elem['last_resolved']
        obj['Domain']='<a href="https://www.virustotal.com/gui/domain/'+elem['hostname']+'/details">'+elem['hostname']+'</a>'
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateScoreHash(self,ip_report_api,attr):
      result=[]
      count=MaxResults[attr] if MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'File Hash (sha256)':""}
        obj['Scanned']=elem['date']
        if elem['positives']==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem['positives'])+"</span>/"+str(elem['total'])
        #response=VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['File Hash (sha256)']='<a href="https://www.virustotal.com/gui/file/'+elem['sha256']+'/detection">'+elem['sha256']+'</a>'
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateScoreURL(self,ip_report_api,attr):
      result=[]
      count=MaxResults[attr] if MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'URL':""}
        obj['Scanned']=elem['scan_date']
        if elem['positives']==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem['positives'])+"</span>/"+str(elem['total'])
        #response=VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['URL']='<a href="https://www.virustotal.com/gui/url/'+hashlib.sha256(elem['url'].encode('utf-8')).hexdigest()+'/detection">'+elem['url']+'</a>'
        result.append(obj)
        count=count-1
      return result

  def formatArrayDateScoreURLnum(self,ip_report_api,attr):
      result=[]
      count=MaxResults[attr] if MaxResults[attr] else -1
      for elem in list(ip_report_api[attr]):
        if count==0:
          break
        obj={'Scanned':"", 'Detections':"",'URL':""}
        obj['Scanned']=elem[4]
        if elem[2]==0:
          color="green"
        else:
          color="red"
        obj['Detections']='<span style="color:'+color+'">'+str(elem[2])+"</span>/"+str(elem[3])
        #response=VTInstance.get_file_report(elem['sha256'])
        #print(response)
        obj['URL']='<a href="https://www.virustotal.com/gui/url/'+elem[1]+'/detection">'+elem[0]+'</a>'
        result.append(obj)
        count=count-1
      return result

  def getNumberMalicious(self,ip_report_api,attr):
      result=[d for d in ip_report_api[attr] if ('positives' in d and d['positives']>0) or ('positives' not in d and d[2]>0)]
      return result

  def getNumberBenign(self,ip_report_api,attr):
      result=[d for d in ip_report_api[attr] if ('positives' in d and d['positives']==0) or ('positives' not in d and d[2]==0)]
      return result

  def updateScoredAttr(self,attr,verdict,result):
      self.number[attr]=self.number[attr] if attr in self.number else {}
      self.number[attr][verdict]=result

  def getIPReportFiltered(self,ip_report_api):
      result={}
      for attr in list(ip_report_api):
        if(attr in DisabledAttr):
          None #del result[attr]
        elif attr=='resolutions':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          self.history[newAttr]=len(ip_report_api[attr])
          result[newAttr]=self.formatArrayDateDomain(ip_report_api,attr)
        elif attr=='detected_referrer_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_referrer_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_downloaded_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_downloaded_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_communicating_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_communicating_samples':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreHash(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        elif attr=='detected_urls':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreURL(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"malicious",len(self.getNumberMalicious(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=tmp+result[newAttr]
          else:
            result[newAttr]=tmp
        elif attr=='undetected_urls':
          newAttr=AttrSubstitution[attr] if attr in AttrSubstitution else attr
          tmp=self.formatArrayDateScoreURLnum(ip_report_api,attr)
          self.updateScoredAttr(newAttr,"benign",len(self.getNumberBenign(ip_report_api,attr)))
          if newAttr in result:
            result[newAttr]=result[newAttr]+tmp
          else:
            result[newAttr]=tmp
        else:
          result[attr]=ip_report_api[attr]
      return result

  def getOrdered(self,ip_report_filtered):
      result={}
      #We order the Order's elements in the begining of the result list
      for elem in Order:
        #If the substitued element index exists in the Order list, then it should be ordered
        if elem in AttrSubstitution and AttrSubstitution[elem] and AttrSubstitution[elem] in ip_report_filtered and ip_report_filtered[AttrSubstitution[elem]]:
          #Ordered elements should not duplicated
          if AttrSubstitution[elem] not in result:
            result[AttrSubstitution[elem]]=ip_report_filtered[AttrSubstitution[elem]]
        #If the index is not substitutable and if the index exists in the Order list, then it should be ordered
        elif elem in ip_report_filtered and ip_report_filtered[elem]:
          #Ordered elements should not duplicated
          if elem not in result:
            result[elem]=ip_report_filtered[elem]
      #Then, we add the non ordered elements since they are not blacklisted so of the Order list is missing some elements, they will be added in the end of the result list
      for attr in list(ip_report_filtered):
        #Ordered elements should not duplicated
        if attr not in result:
          result[attr]=ip_report_filtered[attr]
      return result

  def getHTML(self,ip_report_filtered,ip):
      html=""
      html=html+"<h3>IP Address: "+ip+"</h3>"
      for elem in list(ip_report_filtered):
        html=html+"<h4>"+elem+"</h4>"
        if elem in self.number and self.number[elem]:
          malicious=self.number[elem]["malicious"] if "malicious" in self.number[elem] else 0
          benign=self.number[elem]["benign"] if "benign" in self.number[elem] else 0
          html=html+"<h5>(<span style='color:red'>"+str(malicious)+" malicious</span> and <span style='color:green'>"+str(benign)+" benign</span>)</h5>"
        if elem in self.history and self.history[elem]:
          history=self.history[elem]
          html=html+"<h5>("+str(history)+" found)</h5>"
        html=html+json2html.convert(json = ip_report_filtered[elem], table_attributes='class="'+TablesClass+'"',escape=False)
      self.HTML=self.HTML+html
      html='<html><head>'+HTMLHeader+'</head><body>'+html
      html=html+'</body></html>'
      output=OutputDir+"/"
      #print(html)
      imgkit.from_string(html, output+ip+'-VirusTotal.jpg')
      with open(output+ip+'-VirusTotal.html', 'w') as HTMLFile:
        HTMLFile.write(html)
      self.IMG=self.IMG+"<img src='"+ip+"-VirusTotal.jpg'><br/>"

  def updateGeneralHTML(self):
    HTMLPrefix='<html><head>'+HTMLHeader+'</head><body>'
    self.HTML=HTMLPrefix+self.HTML+'</body></html>'
    self.IMG=HTMLPrefix+self.IMG+'</body></html>'
    output=OutputDir+"/"
    with open(output+'latest-HTML-VirusTotal.html', 'w') as HTMLFile:
      HTMLFile.write(self.HTML)
    with open(output+'latest-IMG-VirusTotal.html', 'w') as HTMLFile:
      HTMLFile.write(self.IMG)

def main():
  vt=VirusTotal()
  vt.init()
  ips_report_api=vt.getIPReportAPI()
  results=[]
  for ip_report_api in list(ips_report_api):
    vt.preHandling()
    ip_report_filtered=vt.getIPReportFiltered(ips_report_api[ip_report_api])
    if len(Order)>0:
      ip_report_filtered=vt.getOrdered(ip_report_filtered)
    vt.getHTML(ip_report_filtered,ip_report_api)
    #results[ip_report_api]=result
  vt.updateGeneralHTML()

if __name__ == "__main__":
    main()
