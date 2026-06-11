import os
import subprocess
import datetime
import re
import json
import socket
import requests

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

def resolution_dns(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "Nom de machine inconnu"

def scan_nmap(ip):
    try:
        commande = ["nmap", "-sVC", "-oG", "-", ip]
        resultat = subprocess.run(commande,capture_output=True,text=True,check=True)
        return resultat.stdout
    except Exception as e:
        raise Exception(f"Erreur lors du scan Nmap : {e}")


def extraire_services(sortie_nmap):
    services = []
    for ligne in sortie_nmap.splitlines():
        if "Ports:" not in ligne:
            continue
        match = re.search(r"Ports:\s*(.*)", ligne)
        if not match:
            continue
        ports_info = match.group(1)
        for port_desc in ports_info.split(","):
            elements = port_desc.strip().split("/")
            if len(elements) < 5:
                continue
            port = elements[0]
            etat = elements[1]
            protocole = elements[2]
            service = elements[4]
            version = "Version inconnue"
            if len(elements) > 6:
                version = "/".join(elements[6:]).strip()
            services.append({"port": port, "protocole": protocole, "etat": etat, "service": service, "version": version})
    return services

def recuperer_cves(service, version, max_resultats=10):
    mot_cle = f"{service} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": mot_cle,"resultsPerPage": max_resultats}
    try:
        reponse = requests.get(url, params=params, timeout=30) 
        reponse.raise_for_status()
        donnees = reponse.json()
        liste_cve = []
        for vuln in donnees.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            liste_cve.append({"id": cve_id, "description": description}) 
        return liste_cve
    except Exception as e:
        return [{"id": "Erreur", "description": str(e)}]

# Correspondance Nmap -> endoflife.date
MAPPING_EOL = {
    "apache": "apache-http-server",
    "apache httpd": "apache-http-server",
    "nginx": "nginx",
    "openssh": "openssh",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "redis": "redis",
    "tomcat": "tomcat",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "php": "php",
    "python": "python",
    "docker": "docker-engine",
    "kubernetes": "kubernetes"
}

def recuperer_fin_support(service, version):
    try:
        service = service.lower().strip()
        if service not in MAPPING_EOL:
            return "Produit non référencé dans le mapping"
        produit = MAPPING_EOL[service]
        morceaux = version.split(".")
        cycle = ".".join(morceaux[:2])
        url = (f"https://endoflife.date/api/v1/"f"products/{produit}/releases/{cycle}")
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return "Cycle non trouvé"
        data = response.json()
        eol = data.get("eol")
        if eol:
            return eol
        support = data.get("support")
        if support:
            return support
        return "Date de fin de support inconnue"
    except Exception as e:
        return f"Erreur EOL : {e}"

def informationsIP(repertoire_retour, nom_fichier_retour, ip):
    os.makedirs(repertoire_retour, exist_ok=True)
    chemin_fichier = os.path.join(repertoire_retour,nom_fichier_retour)
    with open(chemin_fichier, "a", encoding="utf-8") as fichier:
        fichier.write("\n")
        fichier.write("=" * 80 + "\n")
        fichier.write(f"Analyse de l'adresse IP : {ip}\n")
        fichier.write(f"Date : {datetime.now()}\n")
        fichier.write("=" * 80 + "\n\n")
        # Résolution DNS
        hostname = resolution_dns(ip)
        fichier.write(f"Nom de la machine : {hostname}\n\n")
        # Scan Nmap
        sortie_nmap = scan_nmap(ip)
        services = extraire_services(sortie_nmap)
        if not services:
            fichier.write("Aucun port ouvert détecté.\n")
            return
        for srv in services:
            port = srv["port"]
            service = srv["service"]
            version = srv["version"]
            fichier.write("-" * 60 + "\n")
            fichier.write(f"Port : {port}\n")
            fichier.write(f"Service : {service}\n")
            fichier.write(f"Version : {version}\n")
            # Fin de support
            fin_support = recuperer_fin_support(service,version)
            fichier.write(f"Fin de support : {fin_support}\n")
            # CVE
            cves = recuperer_cves(service,version)
            fichier.write("\nCVE associées :\n")
            if not cves:
                fichier.write("Aucune CVE trouvée.\n")
            else:
                for cve in cves:
                    fichier.write(f" - {cve['id']}\n")
                    fichier.write(f"   {cve['description']}\n")
            fichier.write("\n")


folderName = "log" + datetime.date
folderNameNmap = folderName+'/'+'nmap'
subprocess.run(["mkdir", folderName])
subprocess.run(["mkdir", folderNameNmap])
subnets = ["192.168.0.0/24", "192.168.2.0/24"]
listFilesIP = cartographie(subnets, folderNameNmap)
fileIP = extractionIP(listFilesIP, folderNameNmap, folderName)
fileNameRepport = "RapportICO_" + datetime.date
informationsIP(folderName, fileNameRepport)