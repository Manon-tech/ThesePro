import os
import subprocess
import datetime

def cartographie(subnetworks, folderName):
    listFiles = []
    for subnet in subnetworks:
        fileNameIP = "Carto_" + subnet
        filePathIP = folderName + '/' + fileNameIP
        subprocess.run(["nmap", subnet, filePathIP])
        listFiles.append(fileNameIP)
    return listFiles

def extractionIP(filesIP, folderlogNmap, folderIP):
    fIPList = open('listIPOpen.txt')
    for f in filesIP:
        fIP = open(folderlogNmap + f)
        for l in fIP:
            if l.find("Nmap scan report") != -1 and (l+1).find('down') != -1:
                mots = l.split(' ')
                print(mots[-1])
                fIPList.write(mots + '\n')
        fIP.close()
    fIPList.close
    return fIPList

def informationIP(fileName, folderPath):

    return 0

folderName = "log" + datetime.date
folderNameNmap = folderName+'/'+'nmap'
subprocess.run(["mkdir", folderName])
subprocess.run(["mkdir", folderNameNmap])
subnets = ["192.168.0.0/24", "192.168.2.0/24"]
listFilesIP = cartographie(subnets, folderNameNmap)

