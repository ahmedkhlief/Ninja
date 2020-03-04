
def kerb(fname,user,domain):
    #fname="kerberoast/out.txt"
    hashfile="kerberoast/"+user+"@"+domain+"_hashes"
    file=open(fname,"r")
    data=file.read()
    data=data.split("############")
    SPN=data[1]                       # AV data
    Tickets=data[2]                       #  process list
    kerb=data[3]
    Hashes=data[4]
    print "Found Service Principle Names : \n"+SPN
    print "Generated Tickets : \n"+Tickets
    print "Output of Invoke-Kerberoast : \n"+kerb
    print "Hashes saved in "+hashfile
    f=open(hashfile,"a")
    for i in data[4:]:
        print i.strip().replace("\n","")
        f.write(i.strip().replace("\n",""))
    f.close()
