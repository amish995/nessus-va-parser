#!/usr/bin/env python

import argparse
import xml.etree.ElementTree as ET
import xlsxwriter
import re

# Output workbook and worksheet headers
out_WB = 'VA_Summary.xlsx'
WKS_HEADERS = ['Issue', 'Affected IPs', 'Description', 'Plugin Output', 'Solution', 'CVE', 'Severity', 'CVSS Score', 'CVSS Vector']
SUMM_HEADERS = ['IP', 'Number of Issues']
SSL_HEADERS = ['Affected IP', 'Port', 'Ciphers that should not be Removed']
SSH_HEADERS = ['Affected IP', 'Port', 'Algorithms that should not be Removed']
OPEN_PORTS_HEADERS = ['Affected IP', 'Protocol', 'Port']
SSL_ROW = ['Weak SSL Ciphers', 'Please refer to the SSL Ciphers Tab', 'We noted that there were weak SSL ciphers and protocols present on the server.', 'Please refer to the SSL ciphers tab', 'We recommend removing the weak ciphers and protocols.', '', 'Medium']
SSH_ROW = ['Weak SSH Algorithms', 'Please refer to the SSH Algorithms Tab', 'We noted that there were weak SSH Key exchange, MAC and Encryption algorithms, present on the server.', 'Please refer to the SSH Algorithms tab', 'We recommend removing the weak algorithms.', '', 'Low']

# Global IP address variable
IP_ADDR = ''

# Ignore these plugins - they flag SSL and SSH issues which we combine into 1 issue each
IGNORE_PLUGINS = ["70544", "57041", "104743", "121010", "78447", "42873", "26928", "65821", "70658"]
SSH_ITEMS = dict() # Format: {IP_ADDR_1:(port1, ciphers), IP_ADDR_2:(port2, ciphers), ...}
SSL_ITEMS = dict() # Format: {IP_ADDR_1:[(port11, ciphers), (port12, ciphers)], IP_ADDR_2:[(port21, ciphers), (port22, ciphers)], ...}
OPEN_PORTS = dict() # Format: {IP_ADDR_1:[(port11, protocol), (port12, protocol)], IP_ADDR_2:[(port21, protocol), (port22, protocol)], ...}
# Tags to get from each issue item
# Title, port and CVSS are extracted separately
# CVE will also be added separately for the issue as we may need to consolidate more than 1 CVE  
VA_TAGS = ['description', 'solution', 'plugin_output', 'risk_factor']

# Variables used to identify Weak Ciphers and Weak Algos
# Modified from Ivan's script because I am lazy 
# Good to verify the ciphers manually to see if some strong ciphers were flagged as weak
WEAK_CIPHERS = ["SHA1", "1024", "NULL", "blowfish", "3DES", "3des", "cast128", "112", "ECB", "RC4", "DES-CBC3"]
WEAK_ALGOS = ["umac-128", "umac-64", "ripemd", "hmac-sha1", "md5", "blowfish", "cast128", "3des", "128", "aes256-cbc", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "192", "arcfour"]
END_PROTOCOL = ["SSL Version :", "export flag"]

# Finally the dictionaries that consolidate everything
SUMMARY = dict() # Dictionary of issues per IP
CHECK_INFO = dict() # Dictionary of {Issue: [Description, Plugin output, Solution, CVE, Risk, CVSS Base Score, CVSS Vector]}
CHECK_INSTANCE = dict() # Dictionary of {Issue: [IPport1, IPport2, ...]}

# Formatting
line = "="*40 + "\t"

def WriteReport():
    # Initialize the workbook and cell styling
    wb = xlsxwriter.Workbook(out_WB)
    title_format = wb.add_format({'bold': True, 'font_color':'white', 'font_name':'EYInterstate Light', 'bg_color':'black','border':1, 'font_size':10, 'text_wrap':True, 'align':'left', 'valign':'top'})
    normal_format = wb.add_format({'font_name':'EYInterstate Light', 'border':1, 'font_size':10, 'text_wrap':True, 'align':'left', 'valign':'top'})
    
    # Write the summary sheet
    # IP, number of issues
    summ = wb.add_worksheet("Summary")
    for i in range(0, len(SUMM_HEADERS)):
        summ.write(0, i, SUMM_HEADERS[i], title_format)
        summ.set_column(0,i,20) 

    row = 1
    for i in SUMMARY.keys():
        summ.write(row, 0, i, normal_format)
        summ.write(row, 1, SUMMARY[i], normal_format)
        row += 1

    # Write the sheet of issues
    # Issue, Description, Affected IPs, Plugin output, Solution, CVE, Risk, CVSS Base Score, CVSS Vector
    # First, init and add title rows
    issues = wb.add_worksheet("Issues")

    for i in range(0, len(WKS_HEADERS)):
        issues.write(0, i, WKS_HEADERS[i], title_format)
        issues.set_column(i,i,int(len(WKS_HEADERS[i])*1.3))

    # set formatting for specific columns
    issues.set_column(0,0,30) 
    issues.set_column(2,2,80)  
    issues.set_column(3,3,50)
    issues.set_column(4,4,50)
    issues.set_column(5,5,20)
    issues.set_column(8,8,40)

    # Write the issues
    # Rows = Issue, Affected IPs, Description, Plugin output, Solution, CVE, Risk, CVSS Base Score, CVSS Vector
    row = 1
    for chk in CHECK_INFO.keys():
        # Get the first 2 columns done - Issue title and affected IPs
        issues.write(row, 0, chk, normal_format)
        affected = '\n'.join(CHECK_INSTANCE[chk])
        issues.write(row, 1, affected, normal_format)
        # Write the other columns from CHECK_INFO
        # Desc, plugin out, soln, cve, risk, cvss score, cvss vector
        for i in range(0, 7):
            issues.write(row, i+2, CHECK_INFO[chk][i].replace('\t', '\n'), normal_format)
        row += 1

    # Add 2 issues for SSH and SSL ciphers:
    SSL_ROW[1] = '\n'.join(SSL_ITEMS.keys())
    SSH_ROW[1] = '\n'.join(SSH_ITEMS.keys())
    if(SSL_ITEMS.keys()):
        for i in range(0, len(SSL_ROW)):
            issues.write(row, i, SSL_ROW[i], normal_format)
    if(SSH_ITEMS.keys()):
        for i in range(0, len(SSH_ROW)):
            issues.write(row+1, i, SSH_ROW[i], normal_format)

    # Next, add the SSL sheet
    ssl = wb.add_worksheet("SSL Ciphers")
    for i in range(0, len(SSL_HEADERS)):
        ssl.write(0, i, SSL_HEADERS[i], title_format)
    ssl.set_column(0,0,20)
    ssl.set_column(2,2,70)

    row = 1
    for s in SSL_ITEMS.keys():
        temp = 0
        for inst in SSL_ITEMS[s]:
            ssl.write(row+temp, 0, s, normal_format)
            ssl.write(row+temp, 1, inst[0], normal_format)
            ssl.write(row+temp, 2, inst[1].replace('\t','\n'), normal_format)
            temp+=1
        row+=temp
    # Then, add the SSH sheet 
    ssh = wb.add_worksheet("SSH Algorithms")
    for i in range(0, len(SSH_HEADERS)):
        ssh.write(0, i, SSH_HEADERS[i], title_format)
    ssh.set_column(0,0,20)
    ssh.set_column(2,2,70)

    row = 1
    for ip in SSH_ITEMS.keys():
        ssh.write(row, 0, ip, normal_format)
        ssh.write(row, 1, SSH_ITEMS[ip][0], normal_format)
        ssh.write(row, 2, SSH_ITEMS[ip][1].replace('\t','\n'), normal_format)
        row+=1

    # Finally, the Open Ports sheet
    op = wb.add_worksheet("Open Ports")
    for i in range(0, len(OPEN_PORTS_HEADERS)):
        op.write(0, i, OPEN_PORTS_HEADERS[i], title_format)
    op.set_column(0,0,20)

    row = 1
    for o in OPEN_PORTS.keys():
        temp = 0
        for inst in OPEN_PORTS[o]:
            op.write(row+temp, 0, o, normal_format)
            op.write(row+temp, 1, inst[1], normal_format)
            op.write(row+temp, 2, inst[0], normal_format)
            temp+=1
        row+=temp
    
    wb.close()
    return True

# Clean values from nessus report
def getValue(rawValue):
    # Replace the new lines so that it doesnt mess up anything else
    cleanValue = rawValue.replace('\n', '\t').strip(' ')
    # Praise our lord and savior, Regex
    # Removes all the multiple spaces between words that Nessus randomly adds 
    cleanValue = re.sub(' {2,}', ' ', cleanValue)
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
    return cleanValue

# Helper function to add item in a dict
# Parameters: key to check, item to put in, dictionary to put item in 
def addToDict(k, i, d):
    if(k in d.keys()):
        d[k].append(i)
    else:
        d[k] = [i]
    return d

def parseWeakSSL(ciphertext):
    # Get sentences
    list_of_sentences = (ciphertext).split('\n')
    # Basically go thru all sentences, cipherblock is true at the start of ciphers
    # Edit the ciphers when cipherblock is true
    # Change back to false when done 
    cipherblock = False
    badprotocol = False
    items_to_remove = []
    weakprotocol = ""
    for i in range(0, len(list_of_sentences)):
        # See if any of the sentences has a bad protocol or a weak cipher.
        if("SSL Version : " in list_of_sentences[i] and len(list_of_sentences[i]) == 19):
            # SSL v1.0
            weakprotocol = "SSL v1.0"
            badprotocol = True
            add = "\t" + weakprotocol + " was found to be present on the server and should be removed. TLS v1.2 or v1.3 should be used instead." + "\t"
            list_of_sentences[i] += add
            continue
        if("SSL Version : TLSv11" in list_of_sentences[i]):
            # SSL v1.1
            weakprotocol = "SSL v1.1"
            badprotocol = True
            add = "\t" + weakprotocol + " was found to be present on the server and should be removed. TLS v1.2 or v1.3 should be used instead." + "\t"
            list_of_sentences[i] += add
            continue
        if(("---------------------") in list_of_sentences[i] and badprotocol == False):
            # Means its TLS 1.2 or 1.3 and this is where the ciphers are
            cipherblock = True
            add = "\t" + "Only the following SSL Ciphers should remain on the server for this protocol:" + "\t" + "="*50
            list_of_sentences[i-2] += add
            continue
        # If tls v1 or v11, then we flag the entire protocol
        # Dont question the following code, just assume it's magic and trust it
        # Change anything and it's probably going to break
        # Sorry!
        if(badprotocol):
            endcheck = [end for end in END_PROTOCOL if end in list_of_sentences[i]]  
            if(endcheck):
                if("SSL Version : v1" not in list_of_sentences[i]):
                    items_to_remove.append(i)
                    badprotocol = False
                continue
            else:
                items_to_remove.append(i)
                continue
        if(cipherblock):
            # Check if cipher is weak 
            ciphercheck = [weak for weak in WEAK_CIPHERS if(weak in list_of_sentences[i])]  
            # Check if this is end of the block
            endcheck = [end for end in END_PROTOCOL if end in list_of_sentences[i]]
            if(ciphercheck):
                items_to_remove.append(i)
            else:
                list_of_sentences[i] = list_of_sentences[i].split('0x')[0]
            if(endcheck):
                cipherblock = False
                if("SSL Version : " in list_of_sentences[i]):
                    badprotocol = True
                else:
                    items_to_remove.append(i)
                continue

    # Remove the unwanted lines
    for i in sorted(items_to_remove, reverse=True):
        list_of_sentences.pop(i)

    # Join sentences back to get ciphertext
    ciphertext = '\n'.join(list_of_sentences)
    return ciphertext

def parseWeakAlgos(algotext):
    # This should be far more straightforward
    # Go thru all the lines
    # if weak algo phrase exists, remove
    # whooosh
    list_of_sentences = (algotext).split('\n')
    items_to_remove = []
    for i in range(0, len(list_of_sentences)):
        weakalgo = [weak for weak in WEAK_ALGOS if(weak in list_of_sentences[i])]
        if(weakalgo):
            items_to_remove.append(i)

    # Remove unwanted sentences
    for i in sorted(items_to_remove, reverse=True):
        list_of_sentences.pop(i)

    # Join everything back
    algotext = '\n'.join(list_of_sentences)
    return algotext

def getSSH(ssh_item):
    # Get port
    port = ssh_item.attrib['port']
    # Get raw algos
    algos = parseWeakAlgos(ssh_item.find('plugin_output').text)
    # Extract weak algos and add ciphers and port to IP
    SSH_ITEMS[IP_ADDR] = (port, getValue(algos))
    return True

def getSSL(reportItemList):
    for ssl_item in reportItemList:
        # Get port
        port = ssl_item.attrib['port']
        # Get raw ciphers
        ciphers = parseWeakSSL(ssl_item.find('plugin_output').text)
        ciphers = getValue(ciphers)
        # Extract weak ciphers and add ciphers and port to IP
        addToDict(IP_ADDR, (port, ciphers), SSL_ITEMS)
    return True

def getOpenPorts(reportItemList):
    # Get each open port item
    for open_port in reportItemList:
        # Get the port and protocol from attributes
        port = open_port.attrib['port']
        protocol = open_port.attrib['protocol']
        addToDict(IP_ADDR, (port, protocol), OPEN_PORTS)
    return True

# Puts the extracted values into the respective dictionaries
def putValue(issue_dict):
    # First put the results in the CHECK_INFO dictionary
    # Get issue
    title = issue_dict['pluginName']
    # If title isn't added to dictionary, we add it first
    if(title not in CHECK_INFO.keys()):
        # Leave pluginOutput blank - it will be consolidated later
        row = [issue_dict['description'], '',  issue_dict['solution'], issue_dict['cve'], issue_dict['risk_factor'], issue_dict['cvss_base_score'], issue_dict['cvss_vector']]
        CHECK_INFO[title] = row
    # Now we add plugin output
    new_out = "Output for " + IP_ADDR + ":" + "\t" + line + issue_dict['plugin_output'] + "\t" + line
    CHECK_INFO[title][1] += new_out

    # Next, we get the IP:port if it exists and add it to the CHECK_INSTANCE dictionary
    IPport = IP_ADDR
    if(issue_dict['port'] != 0):
        IPport = IP_ADDR + ":" + str(issue_dict['port'])
    addToDict(title, IPport, CHECK_INSTANCE)
    return True

# Handle a single Report Host
def handleReport(report):
    # First get the SSH ouput
    sh_i = report.find("ReportItem/[@pluginID='70657']")
    if(sh_i != None): 
        getSSH(sh_i)
    # Then get all the SSL items
    sl_i = report.findall("ReportItem/[@pluginID='21643']")
    if(sl_i != None): 
        getSSL(sl_i)
    # Then get all the open ports
    op_i = report.findall("ReportItem/[@pluginID='11219']") 
    if(op_i != None):
        getOpenPorts(op_i)
    # Finally, go thru all the 'issue' items that have severity not 0 
    issue_count = 0
    for item in report.findall('ReportItem'):
        if item.attrib['severity'] != "0" and item.attrib['pluginID'] not in IGNORE_PLUGINS:
            # Count issues
            issue_count += 1
            # Create a dictionary of all the tags needed
            issue_dict = dict()
            issue_dict['pluginName'] = item.attrib['pluginName']
            issue_dict['port'] = int(item.attrib['port'])
            # Need to do CVSS separately because some items dont have CVSS or only have CVSS 2.0
            if (item.find("cvss3_base_score") != None):
                issue_dict['cvss_base_score'] = item.find("cvss3_base_score").text
                issue_dict['cvss_vector'] = item.find('cvss3_vector').text
            # CVSS 2.0
            elif (item.find("cvss_base_score") != None):
                issue_dict['cvss_base_score'] = item.find('cvss_base_score').text
                issue_dict['cvss_vector'] = item.find('cvss_vector').text
            # No CVSS 
            else:
                issue_dict['cvss_base_score'] = "NO CVSS BASE SCORE"
                issue_dict['cvss_vector'] = "NO CVSS VECTOR"
            # Get all the other VA tags and put in a dictionary
            for val in VA_TAGS:
                tag_val = item.find(val)
                if(tag_val != None):
                    issue_dict[val] = getValue(tag_val.text)
                else:
                    issue_dict[val] = "No data for " + val
                    print("WARNING: No data for " + val + " for the issue: " + item.attrib['pluginName'])
            # Add CVE 
            cve = []
            for c in item.findall('cve'):
                cve.append(c.text)
            issue_dict['cve'] = '\t'.join(cve)
            # Finally, run the function to put the values for Individual IPs into Global var 
            putValue(issue_dict)
    # Add to Summary global var so that we can make fancy summary sheet
    SUMMARY[IP_ADDR] = issue_count              
    return True

# Get files 
def handleArgs():
    aparser = argparse.ArgumentParser(description='Converts Nessus scan findings from XML to an Excel file with a summary tab. Consolidates IPs with the same issue into 1 row', usage="\n./Nessus-VA-parser.py input1.nessus input2.nessus ...\nAny fields longer than 32,000 characters will be truncated.")
    aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
    args = aparser.parse_args()
    return args.nessus_xml_files

# Main
if __name__ == '__main__':
    reportRows = []
    # For each .nessus file, handle the report items 
    for nessusScan in handleArgs():
        try:
            scanFile = ET.parse(nessusScan)
        except IOError:
            print("Could not find file \"" + nessusScan + "\"")
            exit()
        xmlRoot = scanFile.getroot()
        # Handle each IP inside a report
        for report in xmlRoot.findall('./Report/ReportHost'):
            IP_ADDR = report.find("HostProperties/tag/[@name='host-ip']").text
            res = handleReport(report)
    WriteReport()
    print("Done!")