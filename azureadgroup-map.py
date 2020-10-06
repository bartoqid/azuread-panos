#! /usr/bin/env python3
import re
import requests
import urllib
import urllib3
import getpass
urllib3.disable_warnings()


azure_tenant = input("Please Enter Azure Primary Domain Name: ")
azure_client_id = input("Please Enter Azure Application ID: ")
azure_client_secret = input("Please Enter Azure Application Secret: ")

firewall_ip = input("Please Enter firewall IP: ")
firewall_admin = input("Please Enter firewall username: ")
firewall_password = getpass.getpass("Please enter firewall password: ")


def get_key(firewall_ip, firewall_admin, firewall_password):
    response = requests.get("https://" + firewall_ip + "/api?type=keygen&user=" + firewall_admin + "&password=" + firewall_password, verify=False)
    if re.search(b'success', response.content):
        print("API Key creation successful for device: " + firewall_ip)
    else:
        print("API Key creation failed")
        sys.exit()
    api_key = re.search(b"(<key>)(.+?)(</key>)", response.content).group(2).decode('UTF-8')
    return api_key


# Get Azure authentication token and set in the headers for later use
url = "https://login.microsoftonline.com/" + azure_tenant +  "/oauth2/v2.0/token"
data = {
    "grant_type": "client_credentials",
    "client_id": azure_client_id,
    "scope": "https://graph.microsoft.com/.default",
    "client_secret": azure_client_secret}
r = requests.post(url, data=data)
token = r.json().get("access_token")

headers = {
    "Content-Type" : "application\json",
    "Authorization": "Bearer {}".format(token)
}

# Get List Of Groups from Azure AD

url = "https://graph.microsoft.com/v1.0/groups"
r = requests.get(url, headers=headers)
result = r.json()
groups = result["value"]
# For each group get a list of the members

xmloutput = "<uid-message><type>update</type><payload><groups>"

for group in groups:
    print("-" * 120)
    print(group["displayName"] + " (" + group["id"] + ")")
    xmloutput = xmloutput + "<entry name=\"" + group["displayName"] + "\">"
    xmloutput = xmloutput + "<members>"
    url = "https://graph.microsoft.com/v1.0/groups/" + group["id"] + "/members"
    print(url)
    r = requests.get(url, headers=headers)
    result = r.json()
    users = result["value"]
    for user in users:
        print(" - " + user["userPrincipalName"])
        xmloutput = xmloutput + "<entry name=\"" + user["userPrincipalName"] + "\"/>"
    xmloutput = xmloutput + "</members>"
    xmloutput = xmloutput + "</entry>"
xmloutput = xmloutput + "</groups></payload></uid-message>"
print("-" * 120)

# Make API call to PANW Device

api_key = get_key(firewall_ip,firewall_admin,firewall_password)

encoded = urllib.parse.quote(xmloutput, safe="")
url = "https://" + firewall_ip + "/api/?key=" + api_key + "&type=user-id&cmd=" + encoded
r = requests.get(url, verify=False)



