#Author : SourceCode347
#Website : sourcecode347.com
from subprocess import Popen, PIPE
import random
logo = '''
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||E |||T |||E |||R |||N |||A |||L |||B |||L |||U |||E ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|_________|_________|____|____|____|____|____|____|____|
||       |||       |||S |||C |||A |||N |||N |||E |||R ||
||_______|||_______|||__|||__|||__|||__|||__|||__|||__||
|/_______\|/_______\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|

By SourceCode347
'''
print(logo)
while True:
    a = str(random.randint(0,255))
    b = str(random.randint(0,255))
    c = str(random.randint(0,255))
    d = str(random.randint(0,255))
    target = a+"."+b+"."+c+"."+d
    p = Popen(['nmap', '-p455','--script','smb-vuln-ms17-010',target], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    p_status = p.wait()
    rc = p.returncode
    #print(output)
    if "VULNERABLE" in str(output):
        print("Vuln Found On Target : "+target)
        with open("vulns.txt","a") as f:
            f.write(target+"\n")
            f.close()
