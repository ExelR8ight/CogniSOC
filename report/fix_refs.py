import re

replacements = {
    '@ibm2024breach': '[1]',
    '@unit42_2024': '[2]',
    '@tines2023': '[3]',
    '@chandola2009anomaly': '[4]',
    '@liu2008isolation': '[5]',
    '@scholkopf2001estimating': '[6]',
    '@an2015variational': '[7]',
    '@nslkdd2009': '[8]',
    '@cicids2017': '[9]',
    '@mirsky2018kitsune': '[10]',
    '@ring2019survey': '[11]',
    '@moustafa2016unsw': '[12]',
    '@mitre_attack_2024': '[13]',
    '@sigma_specification': '[14]',
    '@thehive_project': '[15]',
    '@sans_soc_2023': '[16]',
    '@splunk_annual_2024': '[17]',
    '@atomic_red_team': '[18]',
    '@sklearn2011': '[19]',
    '@sysmon_docs': '[20]',
    '@suricata_docs': '[21]'
}

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

for k, v in replacements.items():
    content = content.replace(k, v)

with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
