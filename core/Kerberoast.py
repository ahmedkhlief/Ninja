from core import config


def kerb(fname, user, domain):
    hashfile = f"{config.campaign_name}kerberoast/" + user + "@" + domain + "_hashes"
    file = open(fname, "r")
    data = file.read()
    data = data.split("############")
    SPN = data[1]  # AV data
    Tickets = data[2]  # process list
    kerb = data[3]
    Hashes = kerb.split("*******")
    print("Found Service Principle Names : \n" + SPN)
    print("Generated Tickets : \n" + Tickets)
    print("Output of Invoke-Kerberoast : \n" + kerb)
    print("Hashes saved in " + hashfile)
    f = open(hashfile, "a")
    print(kerb)
    for i in Hashes[1:]:
        i = i + "\n"
        f.write(i + "\n")
    f.close()
