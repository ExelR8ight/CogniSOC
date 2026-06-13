import re

with open('main.typ', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace project name
content = content.replace('PREDICTOR', 'CogniSOC')

# Replace Certificate text
cert_old = r'''This is to certify that the project titled \*"CogniSOC: AI-Powered SOC Threat Detection and Response System"\* has been carried out by \*Ankit Singh\* \(Roll No.: ____________\) under my supervision and guidance during the academic year 2024--2025 in partial fulfillment of the requirements for the award of the degree of \*Bachelor of Technology in Cyber Security\* from \*Noida Institute of Engineering and Technology \(NIET\)\*, Greater Noida, affiliated to Dr. A.P.J. Abdul Kalam Technical University, Lucknow.'''
cert_new = r'''This is to certify that the project titled *"CogniSOC: AI-Powered SOC Threat Detection and Response System"* has been carried out by *Ankit Singh* (Roll No.: ____________) under the supervision and guidance of *Mr. Harinder Sodhi* at *HCLTech* during the academic year 2024--2025. This project was completed in partial fulfillment of the requirements for the award of the degree of *Bachelor of Technology in Cyber Security* from *Noida Institute of Engineering and Technology (NIET)*, Greater Noida, affiliated to Dr. A.P.J. Abdul Kalam Technical University, Lucknow.'''
content = content.replace(cert_old, cert_new)

# Replace Faculty Guide in Title & Certificate
content = content.replace('''________________________ \\
      (Faculty Guide Name) \\
      Department of Cyber Security \\
      NIET, Greater Noida''', '''Mr. Harinder Sodhi \\
      Trainer & Industry Guide \\
      HCLTech''')

content = content.replace('''#line(length: 70%, stroke: 0.5pt) \\
    *Faculty Guide* \\
    Department of Cyber Security \\
    NIET, Greater Noida''', '''#line(length: 70%, stroke: 0.5pt) \\
    *Mr. Harinder Sodhi* \\
    Trainer & Industry Guide \\
    HCLTech''')

# Replace Acknowledgment text
ack_old = r'''First and foremost, I am deeply thankful to my project guide, \*Prof. ____________\*, Department of Cyber Security, NIET, Greater Noida, for providing invaluable guidance, constant encouragement, and constructive feedback throughout the course of this project. Their expertise in cybersecurity and willingness to dedicate time for discussions were instrumental in shaping this work.'''
ack_new = r'''First and foremost, I am deeply thankful to my trainer and industry guide, *Mr. Harinder Sodhi* at *HCLTech*, for providing invaluable guidance, constant encouragement, and constructive feedback throughout the course of this project. His expertise in cybersecurity and willingness to dedicate time for discussions were instrumental in shaping this work.'''
content = content.replace(ack_old, ack_new)

with open('main.typ', 'w', encoding='utf-8') as f:
    f.write(content)
