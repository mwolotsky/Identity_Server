from OpenSSL import SSL
import socket, sys, yaml, time
import DSA1024 as dsa
import AES128 as aes

#Commands
port = 5001
if len(sys.argv) > 1:
    port = int(sys.argv[1])

def loadDB():
    file = open("IdentityDB.yaml","r")
    info = yaml.load(file)
    file.close()
    return info

def exportDB(info):
    file = open("IdentityDB.yaml","w")
    yaml.dump(info,file)
    file.close()

def getUserOrgKey(dict,username,orgname,keytype,keykind,timestamp):
    return dict["Users"][username]["Organizations"][orgname][keytype][keykind][timestamp]["Key"]

def getGroupKey(dict,name,group,keykind,timestamp):
    return dict["Organizations"][name]["Groups"][group][keykind][timestamp]["Key"]

def getOrgKey(dict,orgname,keytype,keykind,timestamp):
    return dict["Organizations"][orgname][keytype][keykind][timestamp]["Key"]

def kind(timestamp):
    if int(timestamp) == 0:
        return "cKey"
    return "oKey"

def stamp(command,path,Data,sent):
    return "{}:{}:{}:{}".format(command,path,Data,sent)

def makeGroup(org,group,user):
    info = loadDB()
    if group not in info["Organizations"][org]["Groups"].keys():
        key = aes.exportKey()
        info["Organizations"][org]["Groups"][group] = {"Members":[user],"SuperUsers":[user],"cKey":{},"oKey":{}}
        info["Organizations"][org]["Groups"][group]["cKey"][0] = {"Key":key}
        current = time.time()
        info["Organizations"][org]["Groups"][group]["oKey"][current] = {"Key":key}
        exportDB(info)
        return current
    else:
        print "ERROR 17: Group Already Exists"
        return False

def groupPrivate(org,group,user,Data):
    try:
        timestamp = Data[2]
        key = Data[3]
    except:
        print "ERROR 33: Invalid Parameters for Group Private"
        print Data
        sys.exit()
    info = loadDB()
    info["Users"][user]["Organizations"][org]["Privates"]["AES"][group] = {timestamp:{"Key":key}}
    exportDB(info)
    return True
    
def addGroup(sender,org,group,user):
    info = loadDB()
    if sender in info["Organizations"][org]["Groups"][group]["SuperUsers"]:
        if user not in info["Organizations"][org]["Groups"][group]["Members"]:
            members = info["Organizations"][org]["Groups"][group]["Members"]
            members.append(user)
            info["Organizations"][org]["Groups"][group]["Members"] = members
            exportDB(info)
            return True
        else:
            print "ERROR 26: User is Already a Member"
            return False
    else:
        print "ERROR 19: Sender Doesn't Have Access to Add New Group Members"
        return False
def addSuper(sender,org,group,user):
    info = loadDB()
    if sender in info["Organizations"][org]["Groups"][group]["SuperUsers"]:
        if user not in info["Organizations"][org]["Groups"][group]["SuperUsers"]:
            supers = info["Organizations"][org]["Groups"][group]["SuperUsers"]
            supers.append(user)
            info["Organizations"][org]["Groups"][group]["SuperUsers"] = supers
            exportDB(info)
            addGroup(sender,org,group,user)
            return True
        else:
            print "ERROR 27: User is Already a SuperUser"
            return False
    else:
        print "ERROR 20: Sender Doesn't Have Access to Add New Super Users"
        return False
def removeGroup(sender,org,group,user):
    info = loadDB()
    if sender in info["Organizations"][org]["Groups"][group]["SuperUsers"]:
        members = info["Organizations"][org]["Groups"][group]["Members"]
        if user in members:
            if user not in info["Organizations"][org]["Groups"][group]["SuperUsers"]:
                members.remove(user)
                info["Organizations"][org]["Groups"][group]["Members"] = members
                exportDB(info)
                return True
            else:
                print "ERROR 28: User is a SuperUser and Cannot be Removed From Group"
                return False
        print "ERROR 21: User Is Not A Member of the Group"
        return False
    else:
        print "ERROR 22: Sender Doesn't Have Access to Remove Group Members"
        return False
#Path is the Organization/Group Information of Target
#Data is the list of subdirectories [User,Keytype]
def postSetting(path,Data):
    try:
        user = Data[0]
        keytype = Data[1]
    except:
        print "ERROR 2: Invalid Data Parameters for Post Settings"
        print Data
        sys.exit()
    file = open("IdentityDB.yaml","r")
    info = yaml.load(file)
    file.close()
    #Cut Path
    Path = path.split("/")
    type = Path[0]
    name = Path[1]
    info["Users"][user][type][name][keytype]["Post"] = True
    file = open("IdentityDB.yaml","w")
    yaml.dump(info,file)
    file.close()
#Currently only set for users    
def postKey(path,Data):
    try:
        user = Data[0]
        keytype = Data[1]
        key = Data[2]
    except:
        print "ERROR 3: Invalid Data Parameters for Post Key"
        print Data
        sys.exit()
    file = open("IdentityDB.yaml","r")
    info = yaml.load(file)
    file.close()
    #Cut Path
    Path = path.split("/")
    type = Path[2]
    name = Path[3]
    timestamp = time.time()
    if info["Users"][user][type][name][keytype]["Post"] == True:
        info["Users"][user][type][name][keytype]["oKey"][timestamp] = {"Key":key}
        info["Users"][user][type][name][keytype]["cKey"][0] = {"Key":key}
        info["Users"][user][type][name][keytype]["Post"] = False
        exportDB(info)
        return timestamp
    else:
        print "ERROR 12: Posting Not Enabled"
        sys.exit()

def postPrivate(path,Data):
    try:
        user = Data[0]
        keytype = Data[1]
        key = Data[3]
        timestamp = Data[2]
    except:
        print "ERROR 30: Invalid Data Parameters for Post Private"
        print Data
        sys.exit()
    info = loadDB()
    Path = path.split("/")
    type = Path[2]
    name = Path[3]
    try:
        info["Users"][user][type][name]["Privates"][keytype]["oKey"][timestamp] = {"Key":key}
        info["Users"][user][type][name]["Privates"][keytype]["cKey"][0] = {"Key":key}
        exportDB(info)
        return True
    except:
        print "ERROR 31: Post Private Failed Posting to DataBase"
        return False

def getUsers(name,Data):
    try:
        user = Data[0]
        keytype = Data[1]
        timestamp = Data[2]
    except:
        print "ERROR 5: Invalid Data Parameters for Get Organizations"
        print Data
        sys.exit()
    if timestamp == 0:
        timestamp = 0
        keykind = "cKey"
    else:
        keykind = "oKey"
        timestamp = float(timestamp)
    info = loadDB()
    return getUserOrgKey(info,user,name,keytype,keykind,timestamp)
    
def getGroups(name,group,Data):
    try:
        user = Data[0]
        timestamp = Data[1]
    except:
        print "ERROR 6: Invalid Data Parameters for Get Groups"
        print Data
        sys.exit()
    if timestamp == 0:
        keykind = "cKey"
        timestamp = 0
    else:
        keykind = "oKey"
        timestamp = float(timestamp)
    info = loadDB()
    Members = info["Organizations"][name]["Groups"][group]["Members"]
    if user in Members:
        return getGroupKey(info,name,group,keykind,timestamp)
    else:
        print "ERROR 7: User Not a Member of Group"
        return False

def getOrganizations(name,Data):
    try:
        keytype = Data[0]
        timestamp = Data[1]
    except:
        print "ERROR 9: Invalid Data Parameters for Get Organizations"
        print Data
        sys.exit()
    keykind = kind(timestamp)
    if keykind == "cKey":
        timestamp = 0
    else:
        timestamp = float(timestamp)
    info = loadDB()
    return getOrgKey(info,name,keytype,keykind,timestamp)
    
def getKey(path,Data):
    try:
        Path = path.split("/")
        type = Path[0]
        name = Path[1]
        if type == "Users":
            return getUsers(name,Data)
        elif type == "Organizations":
            return getOrganizations(name,Data)
        elif type == "Groups":
            group = Path[2]
            return getGroups(name,group,Data)
    except:
        print "ERROR 4: Invalid Type Parameter for Get Key"
        print path
        sys.exit()
 
def markKey(path,Data):
    try:
        Path = path.split("/")
        type = Path[0]
        name = Path[1]
        user = Data[0]
        keytype = Data[1]
        timestamp = Data[2]
        mark = Data[3]
    except:
        print "ERROR 8: Invalid Parameters for Mark Key"
        print path
        print Data
        sys.exit()  
    if timestamp == 0:
        keykind = "cKey"
        timestamp = 0
    else:
        keykind = "oKey"
        timestamp = float(timestamp)
    info = loadDB()
    info["Users"][user]["Organizations"][name][keytype][keykind][timestamp]["Status"] = mark
    exportDB(info) 
 
def verifySignature(user,org,time,signature,stamped):
    dsaKey = getKey("Users/{}".format(org),[user,"DSA",sent])
    dsaSig = dsa.constructDSAPublic(dsaKey)
    if dsa.verifyMessage(dsaSig,stamped,signature):
        return True
    return False
        
def verifyCommand(command,path,Data,sent,signature):
    if command == "PostSetting":
        dsaKey = getKey(path,["DSA",sent])
        dsaSig = dsa.constructDSAPublic(dsaKey)
        if dsa.verifyMessage(dsaSig,stamp(command,path,Data,sent), signature):
            postSetting(path,Data)
            return True
        else:
            print "ERROR 11: Signature Could Not Be Verified"
            sys.exit()
    #No Signature is used, Apple Signature is necessary
    elif command == "Post":
        Path = path.split("/")
        user = Path[1]
        name = Path[3]
        #dsaKey = getKey("Users/{}/{}".format(user,name),[user,"DSA",sent])
        #dsaSig = dsa.constructDSAPublic(dsaKey)
        #if dsa.verifyMessage(dsaSig,stamp(command,path,Data,sent),signature):
        try:
            return postKey(path,Data)
        except:
            print "ERROR 13: Post Key Failed"
            return False
    elif command == "PostPrivate":
        Path = path.split("/")
        user = Path[1]
        name = Path[3]
        try:
            postPrivate(path,Data)
            return True
        except:
            print "ERROR 29: Post Private Failed"
            return False
    elif command == "Create":
        user = Data[0].strip("\'")
        try:
            info = loadDB()
            users = info["Users"].keys()
            if user in users:
                raise Exception("User Already Exists")
            info["Users"][user] = {"Organizations":{"TigerText":{"Privates":{"DSA":{"cKey":{},"oKey":{}},"RSA":{"cKey":{},"oKey":{}},"AES":{}},"DSA":{"Post":True,"cKey":{},"oKey":{}},"RSA":{"Post":True,"cKey":{},"oKey":{}}}}}
            exportDB(info)
            return True
        except:
            print "Error Creating User"
            return False
    elif command == "MakeGroup":
        Path = path.split("/")
        user = Path[0]
        name = Path[1]
        group = Path[2]
        stamped = stamp(command,path,[],sent)
        verified = verifySignature(user,name,sent,signature,stamped)
        if verified:
            return makeGroup(name,group,user)
        else:
            print "ERROR 18: Signature Could Not Be Verified"
            sys.exit()
    elif command == "GroupPrivate":
        Path = path.split("/")
        user = Path[0]
        name = Path[1]
        group = Path[2]
        stamped = stamp(command,path,[],sent)
        verified = verifySignature(user,name,sent,signature,stamped)
        if verified:
            return groupPrivate(name,group,user,Data)
        else:
            print "ERROR 32: Group Private Could Not Be Verified"
            sys.exit()
    elif command == "AddGroup":
        Path = path.split("/")
        sender = Path[0]
        org = Path[1]
        group = Path[2]
        user = Data[0]
        stamped = stamp(command,path,Data,sent)
        verified = verifySignature(sender,org,sent,signature,stamped)
        if verified:
            return addGroup(sender,org,group,user)
        else:
            print "ERROR 23: Signature Could Not Be Verified"
            sys.exit()
    elif command == "AddSuper":
        Path = path.split("/")
        sender = Path[0]
        org = Path[1]
        group = Path[2]
        user = Data[0]
        stamped = stamp(command,path,Data,sent)
        verified = verifySignature(sender,org,sent,signature,stamped)
        if verified:
            return addSuper(sender,org,group,user)
        else:
            print "ERROR 24: Signature Could Not Be Verified"
            sys.exit()
    elif command == "RemoveGroup":
        Path = path.split("/")
        sender = Path[0]
        org = Path[1]
        group = Path[2]
        user = Data[0]
        stamped = stamp(command,path,Data,sent)
        verified = verifySignature(sender,org,sent,signature,stamped)
        if verified:
            return removeGroup(sender,org,group,user)
        else:
            print "ERROR 25: Signature Could Not Be Verified"
            sys.exit()
    elif command == "Get":
        Path = path.split("/")
        type = Path[0]
        if type == "Users" or type == "Organizations":
            user = Path[1]
            name = Path[2]
            dsaKey = getKey("Users/{}".format(name),[user,"DSA",sent])
            dsaSig = dsa.constructDSAPublic(dsaKey)
            if dsa.verifyMessage(dsaSig,stamp(command,path,Data,sent),signature):
                return getKey("{}/{}".format(type,name),Data)
            else:
                print "ERROR 14: Signature Could Not Be Verified"
                sys.exit()
        elif type == "Groups":
            user = Path[1]
            name = Path[2]
            group = Path[3]
            dsaKey = getKey("Users/{}".format(name),[user,"DSA",sent])
            dsaSig = dsa.constructDSAPublic(dsaKey)
            if dsa.verifyMessage(dsaSig,stamp(command,path,Data,sent),signature):
                return getKey("Groups/{}/{}".format(name,group),[user,Data[0]])
            else:
                print "ERROR 15: Signature Could Not Be Verified"
                sys.exit()
    elif command == "NewDevice":
        try:
            Path = path.split("/")
            user = Path[1]
            org = Path[2]
            info = loadDB()
            return info["Users"][user]["Organizations"][org]["Privates"]
        except:
            print "ERROR 34: New Device Information Not Found"
            return False
    elif command == "Mark":
        dsaKey = getKey(path,["DSA",sent])
        dsaSig = dsa.constructDSAPublic(dsaKey)
        if dsa.verifyMessage(dsaSig,stamp(command,path,Data,sent), signature):
            markKey(path,Data)
            return True
        else:
            print "ERROR 16: Signature Could Not Be Verified"
            sys.exit()
        return
    else:
        print "ERROR 10: Invalid Command for Verification"
        print command
        sys.exit() 

#Establish SSL 
context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('key')
context.use_certificate_file('cert')

#Open SSL Socket on Port 5001 on Localhost
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock = SSL.Connection(context,sock)
sock.bind(('',port))
sock.listen(5)
(connection,address) = sock.accept()


def write(message):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        sock.connect(("localhost",port + 1))
    except:
        print "Unable to Connect"
        sys.exit()
    sslSocket = socket.ssl(sock)
    sslSocket.write("{}".format(message))
    sock.close()

#On Receiving a Message
while True:
    received = repr(connection.recv(65535))
    #Message in Format COMMAND:PATH:SENDER:DATA:SIGNATURE 
    if "PostPrivate" in received or "GroupPrivate" in received:
        try:
            if "PostPrivate" in received:
                Info = received.split(":",3)
            else:
                Info = received.split(":",4)
            
            command = Info[0].strip("\'")
            path = Info[1]
            print command
            print path
            if "PostPrivate" in received:
                Info[3] = Info[3].strip("[]")
                data = Info[3].split(",",3)
            else:
                Info[4] = Info[4].strip("[]")
                data = Info[4].split(",",3)
                print Info[3]
                signature = Info[3].strip("\"")
                signature = signature.strip("\'")
                sigs = signature.split(",")
                for i in range(len(sigs)):
                    sigs[i] = long(sigs[i].strip("() "))
                signature = tuple(sigs)
                print signature
            data[0] = data[0].strip("\\")
            data[0] = data[0].strip("\'")
            data[0] = data[0].strip("\\")
            print data[0]
            data[1] = data[1].strip(" ")
            data[1] = data[1].strip("\\")
            data[1] = data[1].strip("\'")
            data[1] = data[1].strip("\\")
            print data[1]
            data[2] = data[2].strip(" ")
            data[2] = data[2].strip("\"")
            data[2] = data[2].strip("\\")
            data[2] = data[2].strip("\'")
            data[2] = data[2].strip("\\")
            data[2] = float(data[2])
            print data[2]
            data[3] = data[3].strip(" ")
            data[3] = data[3].strip("\\")
            data[3] = data[3].strip("\'")
            data[3] = data[3].strip("]")
            data[3] = data[3].strip("\'")
            data[3] = data[3].strip("\\")
            data[3] = data[3].replace("\\\\","\\")
            Data = data
            Info[2] = Info[2].strip("\'")
            Info[2] = Info[2].strip("\"")
            Info[2] = Info[2].strip("\\\\\\")
            sent = float(Info[2])
            print sent
        except:
            print "Exception in PostPrivate or GroupPrivate"
            print received
            write("False")
            sys.exit()
    else:
        try:
            Info = received.split(":")
            command = Info[0].strip("\"")
            command = command.strip("\'")
            path = Info[1]
            #Data is in Array form but in string so strip [] and split ,'s
            Data = Info[2]
            Data = Data.strip("[]")
            Data = Data.replace("\\\\n","\n")
            Data = Data.replace("\'","")
            Data = Data.split(",")
            for i in range(len(Data)):
                Data[i] = Data[i].strip(" ")
                try:
                    Data[i] = float(Data[i])
                except:
                    pass
            print Data
            Info[3] = Info[3].strip("\'")
            sent = float(Info[3].strip("\""))
            print command
            print path
            print sent
            if len(Info) > 4:
                signature = Info[4].strip("\"")
                signature = signature.strip("\'")
                sigs = signature.split(",")
                for i in range(len(sigs)):
                    sigs[i] = long(sigs[i].strip("() "))
                signature = tuple(sigs)
                print signature
            else:
                signature = None
            print "-" * 80
        except:
            print "ERROR 1: Invalid Parameters Received from Socket"
            print received
            write("False")
            sock.close()
            sys.exit()        
    write(verifyCommand(command,path,Data,sent,signature))
