#Author : SourceCode347
#Website : sourcecode347.com
from subprocess import Popen, PIPE
import random , sys
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
def detect(target):
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
r_args=['-a','-b']
aval = False
bval = False
for arg in range(0,len(sys.argv)):
    if sys.argv[arg-1]=="-a":
        aval=str(sys.argv[arg])
        
while True:
    if aval == False and bval == False:
        try:
            for a in range(0,255):
                for b in range(0,255):
                    for c in range(0,255):
                        for d in range(0,255):
                            target = str(a)+"."+str(b)+"."+str(c)+"."+str(d)
                            detect(target)
        except:
            pass
    if aval != False and bval == False:
        try:
            a=aval
            for b in range(0,255):
                for c in range(0,255):
                    for d in range(0,255):
                        target = str(a)+"."+str(b)+"."+str(c)+"."+str(d)
                        detect(target)
        except:
            pass
    if aval != False and bval != False:
        try:
            a=aval
            b=aval
            for c in range(0,255):
                for d in range(0,255):
                    target = str(a)+"."+str(b)+"."+str(c)+"."+str(d)
                    detect(target)
        except:
            pass
