import socket, sys, yaml, time
import DSA1024 as dsa, RSA1280 as rsa
from Crypto.Hash import MD5, SHA
from OpenSSL import SSL
import AES128 as aes

#Default The communication port for Sending on 5001, Receiving on 5002
port = 5001

#Change Default Port for Sending to X, Receiving on X+1
if len(sys.argv) > 1:
    port = int(sys.argv[1])

#Global username used to keep track of who is logged in    
username = None

#Loads the Database file in Dictionary Format
def loadDB():
    file = open("AccountDB.yaml","r")
    info = yaml.load(file)
    file.close()
    return info
def loadKeys():
    file = open("PrivateKeys.yaml","r")
    info = yaml.load(file)
    file.close()
    return info

#Stores a Dictionary object into a Database File
def exportDB(info):
    file = open("AccountDB.yaml","w")
    yaml.dump(info,file)
    file.close()
def exportKeys(info):
    file = open("PrivateKeys.yaml","w")
    yaml.dump(info,file)
    file.close()

#Handles Terminal Input  
def prompt():
    global username
    if username == None:
        sys.stdout.write('<Client Device> ')
    #If User is logged in, display username
    else:
        sys.stdout.write('<Client Device/{}> '.format(username))
    sys.stdout.flush()
 
#Stamp is a way to combine the data being sent over SSL into a singular format
#This singular object is hashed and signed so it can be used to verify that the initial request wasn't
#Modified during transit   
def stamp(command,path,Data,sent):
    return "{}:{}:{}:{}".format(command,path,Data,sent)

#Update the current Public Key of a given type on the Identity Server
#Standard Signatures cannot be used because one must assume that there is no DSA Key available
#Apple/Android Store Signatures should instead be used, however cannot be shown in Python example
def post(type):
    global username
    if username != None:
        command = "Post"
        #Organization in this test is constant, can be any not only TigerText
        path = "Users/{}/Organizations/TigerText".format(username)
        #Only valid choices are DSA or RSA for generating Public Keys
        if "dsa" in type.lower():
            Type = "DSA"
            keys = dsa.generateKeys()
        elif "rsa" in type.lower():
            Type = "RSA"
            keys = rsa.keyArray()
        else:
            return False
        private = keys[0]
        public = keys[1]
        Data = [username,Type,public]
        #The Return Value is the information to be sent over SSL and the private key to be stored locally
        return [command,path,Data,private]
    return False

#Private keys should be encrypted using a hash of the user's password (not the same hash used for authentication)
#And stored on the Identity Server, this allows New Devices of the same user to access the encrypted Private Keys
#And Decrypt them using the User's password
def postPrivate(type,private,password,timestamp):
    global username
    if username != None:
        command = "PostPrivate"
        #TigerText is a constant for testing, can be any organization
        path = "Users/{}/Organizations/TigerText".format(username)
        #Only DSA and RSA are valid in this kind of post, similar to previous
        if "dsa" in type.lower():
            Type = "DSA"
        elif "rsa" in type.lower():
            Type = "RSA"
        else:
            return False
        #This uses the user's password hash in order to generate an AES key
        key = aes.passToKey(password)
        #Encrypts the RSA/DSA private key with the generated AES key
        cipher = aes.encrypt(private, key)
        Data = [username,Type,timestamp,cipher]
        #Information needed to be sent over SSL
        return [command,path,Data]
    return False

#Any user who can be verified (Has a DSA Key) should be able to make a group
def makeGroup(group):
    global username
    if username != None:
        command = "MakeGroup"
        path = "{}/TigerText/{}".format(username,group)
        Data = []
        return [command,path,Data]
    return False

#Group Member-Only Keys should be encrypted and sent up to the Identity Server so that new devices can access them
def groupPrivate(group,private,password,timestamp):
    global username
    if username != None:
        command = "GroupPrivate"
        path = "{}/TigerText/{}".format(username,group)
        #This uses the user's password hash in order to generate an AES key
        key = aes.passToKey(password)
        #Encrypts the RSA/DSA private key with the generated AES key
        cipher = aes.encrypt(private,key)
        Data = [username,"AES",timestamp,cipher]
        return [command,path,Data]
    return False

#Get the Public Key of a user from the identity server in order to send them a message
#This means that the key you need is an RSA key and you need the most current key
def getSend(name):
    global username
    if username != None:
        command = "Get"
        #TigerText is constant
        path = "Users/{}/TigerText".format(username)
        user = name
        #RSA Keys are used for encrypting messages to be sent
        type = "RSA"
        #The timestamp 0 represents the most recent key, to send a message you want to send it to a user's
        #Most current key
        time = 0.0
        Data = [user,type,time]
        return [command,path,Data]
    return False

#Get the Group Server Key from the server (for sending, receiving needs to be configured)
def getGroup(group):
    global username
    if username != None:
        command = "Get"
        #TigerText is constant
        path = "Groups/{}/TigerText/{}".format(username,group)
        #Most current key (for sending, receiving needs to be configured)
        time = 0.0
        Data = [time]
        return [command,path,Data]
    return False

#Gets all of the Encrypted Private Keys for a user from the Identity Server
def newDevice():
    global username
    if username != None:
        command = "NewDevice"
        #TigerText is constant
        path = "Users/{}/TigerText".format(username)
        return [command,path,[]]
    return False

#Get the Public Key of a user from the identity server in order to receive a message from them
#You need the RSA Key which has the timestamp of the received message
def getReceive(name,time):
    global username
    if username != None:
        command = "Get"
        #TigerText is constant
        path = "Users/{}/TigerText".format(username)
        user = name
        #RSA is needed for decrypting received messages
        type = "RSA"
        #The timestamp on the received message is needed to find the correct key to decrypt the message
        time = float(time)
        Data = [user,type,time]
        return [command,path,Data]
    return False

#Add a member to a given group, can only be done by a superuser of the group
def groupAdd(user,group):
    global username
    if username != None:
        command = "AddGroup"
        #TigerText is constant
        path = "{}/TigerText/{}".format(username,group)
        Data = [user]
        return [command,path,Data]
    return False

#Remove a member from a given group, can only be done by a superuser of the group
def groupRemove(user,group):
    global username
    if username != None:
        command = "RemoveGroup"
        path = "{}/TigerText/{}".format(username,group)
        Data = [user]
        return [command,path,Data]
    return False

#Add a superuser to a given group, can only be done by a superuser of the group
def groupSuper(user,group):
    global username
    if username != None:
        command = "AddSuper"
        path = "{}/TigerText/{}".format(username,group)
        Data = [user]
        return [command,path,Data]
    return False

#Checks to see if a user has already been created
def canCreate(user):
    info = loadDB()
    #User doesn't already exist
    if user not in info["Users"].keys():
        return True
    return False

#Makes a new account
def createAccount(user,password):
    #A hash of the user's password to be stored
    hashpass = MD5.new(password).digest()
    info = loadDB()
    #User does not already exist
    if user not in info["Users"].keys():
        info["Users"][user] = hashpass
        exportDB(info)
        info = loadKeys()
        #Default Information for a New User
        info["Users"][user] = {"DSA": {},"RSA":{},"AES":{}}
        exportKeys(info)
        return True
    return False

#Login as an established account
def login(user,password):
    global username
    if username == None:
        hashpass = MD5.new(password).digest()
        info = loadDB()
        #Compare the password hash's to verify password is correct
        if info["Users"][user] == hashpass:
            username = user
            return True
    return False

#Create a communication Socket
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
    #Connect to the Identity Server locally on given port
    sock.connect(("localhost",port))
except:
    print "Unable to Connect"
    sys.exit()

#Establish SSL communication over Socket
sslSocket = socket.ssl(sock)

print "Connected to Identity Server"
#Accept input from the terminal
prompt()

#Receive communication from the identity server on a different port than the socket being sent
def listen():
    #Define the SSL information: The Public Key and the Certificate of the Receiver
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_privatekey_file('key')
    context.use_certificate_file('cert')

    #Accept an SSL connection on the socket on the given port
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock = SSL.Connection(context,sock)
    sock.bind(('',port + 1))
    sock.listen(5)
    
    #Store the information of the device connecting to socket
    (connection,address) = sock.accept()
    
    #Accept information over the socket and return it
    received = repr(connection.recv(65535))
    sock.close()
    return received

while True:
    #Read in commandline input
    input = sys.stdin.readline().strip("\n")
    
    #List of All Commands with Parameters
    if "help" in input.lower():
        print "Here are a List of Possible Commands:"
        print "CreateAccount <Username> <Password>"
        print "Login <Username> <Password>"
        print "Post <RSA|DSA>"
        print "GetSend <Username>"
        print "GetReceive <Username> <Time>"
        print "MakeGroup <GroupName>"
        print "GetGroup <GroupName>"
        print "GroupAdd <Username> <GroupName>"
        print "GroupRemove <Username> <GroupName>"
        print "GroupSuper <Username> <GroupName>"
        print "Clear Administrator"
        print "NewDevice"
        print "Logout"
        print "Exit"
        
    else:
        inData = input.split(" ")
        
        #Initiates the Post command
        if inData[0].lower() == "post":
            #Transforms Post <Keytype> to format to be sent through SSL
            output = post(inData[1])
            if output == False:
                print "Invalid Parameters for Post"
            else:
                sent = 0.0
                #Send the necessary data over SSL, Signature not included on Post
                #Becase no signature is included, sent value is irrelevant
                #Socket = Post:Users/<username>/Organizations/TigerText<Or any Organization>:[<username>,<keytype>,<key>]:
                sslSocket.write("{}:{}:{}:{}".format(output[0],output[1],output[2],sent))
                #Accept Answer for the previous request
                received = listen()
                if "False" not in received:
                    #Locally store the private key corresponding to the posted public key
                    info = loadKeys()
                    info["Users"][username][output[2][1]] = output[3]
                    #Parse the user's password hash (different than the password hash used for authentication)
                    password = info["Users"][username]["Password"]
                    exportKeys(info)
                    print "Post Successful"
                    #Transforms private key, keytype, and password hash to be sent through SSL
                    nextoutput = postPrivate(inData[1],output[3],password,received)
                    #Stop pointing anything to the password hash, it's insecure to leave it in memory
                    password = None
                    if nextoutput == False:
                        print "Invalid Parameters for Post Private"
                    else:
                        sent = 0.0
                        #Send the necessary data over SSL, Signature not included for Posting the private
                        #Signature can be included (it would be more secure) iff post DSA is done before post RSA
                        #Sent value is only relevant if signature is also included
                        #Socket = PostPrivate:Users/<username>/Organizations/Tigertext<any>:[<username>,<keytype>,<key>]:
                        sslSocket.write("{}:{}:{}:{}".format(nextoutput[0],nextoutput[1],sent,nextoutput[2]))
                        received = listen()
                        if "True" in received:
                            print "Post Private Successful"
                        else:
                            print "Post Private Failed"
                else:
                    print "Invalid Post Request"
       
        #This command empties the stored databases and only leaves necessary backbone 
        elif inData[0].lower() == "clear":
            if "admin" in inData[1].lower():
                info = {"Users":{}}
                exportKeys(info)
                exportDB(info)
                #Necessary Backbone
                info = {"Users":{},"Organizations":{"TigerText":{"Groups":{}}}}
                #In this test just locally emptying IdentityServer, not relevant in real systems
                file = open("IdentityDB.yaml","w")
                yaml.dump(info,file)
                file.close()
                username = None
                print "Databases Have Been Cleared Successfully"
            else:
                print "Clear Failed, Try: Clear admin"
        
        #Gets The RSA Public Key of an input user in order to send them a message   
        #Because it is for the purpose of sending a message, the current RSA Public Key of the target is necessary     
        elif inData[0].lower() == "getsend":
            #Transforms GetSend <Username> into data for SSL
            output = getSend(inData[1])
            if output == False:
                print "Invalid Parameters for Get Send"
            else:
                #For testing purposes sent is always 0 referring to the senders most recent DSA key
                sent = 0.0
                #Generate a Signature using the sender's Private DSA Key
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                #Stamped creates a single string representation of the command
                #So that it can be hashed and used as an accurate signature
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig, stamped)
                #Send the data over SSL. Socket = 
                #GetSend:Users/<sender>/TigerText:[target,RSA,0]:sent:sig
                #Target refers to user to get key of, 0 refers to the current key
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                #Receive the requested key
                received = listen()
                received = received.replace("\\n","\n")
                print received
        elif inData[0].lower() == "getgroup":
            output = getGroup(inData[1])
            if output == False:
                print "Invalid Parameters for Get Group"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig,stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                received = received.replace("\\n","\n")
                if "False" in received:
                    print "Invalid Parameters for Get Group"
                else:
                    print received
        elif inData[0].lower() == "getreceive":
            output = getReceive(inData[1],inData[2])
            if output == False:
                print "Invalid Parameters to Get Receive"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig,stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                received = received.replace("\\n","\n")
                print received
        elif "logout" in input.lower():
            if username == None:
                print "Was Not Logged In"
            else:
                print "Successfully Logged Out"
                info = loadKeys()
                info["Users"][username]["Password"] = None
                exportKeys(info)
                username = None
        elif "makegroup" in input.lower():
            output = makeGroup(inData[1])
            if output == False:
                print "Invalid Parameters to Make Group"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig,stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                if "False" not in received:
                    info = loadKeys()
                    key= aes.exportKey()
                    info["Users"][username]["AES"][inData[1]] = key
                    password = info["Users"][username]["Password"]
                    exportKeys(info)
                    print "Group Creation Successful"
                    nextoutput = groupPrivate(inData[1],key,password,received)
                    password = None
                    if nextoutput == False:
                        print "Invalid Parameters for Group Private"
                    else:
                        sent = 0.0
                        stamped = stamp(nextoutput[0],nextoutput[1],[],sent)
                        signature = dsa.signMessage(sig, stamped)
                        sslSocket.write("{}:{}:{}:{}:{}".format(nextoutput[0],nextoutput[1],sent,signature,nextoutput[2]))
                        received = listen()
                        if "True" in received:
                            print "Group Private Successful"
                        else:
                            print "Group Private Failed"
                else:
                    print "Group Creation Failed"
        elif inData[0].lower() == "groupadd":
            output = groupAdd(inData[1],inData[2])
            if output == False:
                print "Invalid Parameters for Group Add"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig, stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                if "True" in received:
                    print "User Added Successfully"
                else:
                    print "User Could Not Be Added To Group"
        elif inData[0].lower() == "groupremove":
            output = groupRemove(inData[1],inData[2])
            if output == False:
                print "Invalid Parameters for Group Remove"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig, stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                if "True" in received:
                    print "User Removed Successfully"
                else:
                    print "User Could Not Be Removed From Group"
        elif "newdevice" in inData[0].lower():
            output = newDevice()
            if output == False:
                print "Invalid Parameters for New Device"
            else:
                sent = 0.0
                sslSocket.write("{}:{}:{}:{}".format(output[0],output[1],output[2],sent))
                received = listen()
                if "False" not in received:
                    print received
                else:
                    print "New Device Information Could Not Be Loaded"
        elif inData[0].lower() == "groupsuper":
            output = groupSuper(inData[1],inData[2])
            if output == False:
                print "Invalid Parameters for Group Super"
            else:
                sent = 0.0
                info = loadKeys()
                private = info["Users"][username]["DSA"]
                sig = dsa.constructDSAPrivate(private)
                stamped = stamp(output[0],output[1],output[2],sent)
                signature = dsa.signMessage(sig, stamped)
                sslSocket.write("{}:{}:{}:{}:{}".format(output[0],output[1],output[2],sent,signature))
                received = listen()
                if "True" in received:
                    print "Super Added Successfully"
                else:
                    print "Super Could Not Be Added To Group"            
        elif inData[0].lower() == "login":
            if login(inData[1],inData[2]):
                print "Login Successful"
                hash = SHA.new()
                hash.update(inData[2])
                hashed = hash.hexdigest()
                info = loadKeys()
                info["Users"][username]["Password"] = hashed
                exportKeys(info)  
            else:
                print "Login Failed"
        elif inData[0].lower() == "createaccount":
            if canCreate(inData[1]):
                sslSocket.write("Create:{}:{}:{}".format("None",inData[1],0.0))
                received = listen()
                if "True" in received:
                    createAccount(inData[1],inData[2])
                    print "Account Creation Successful"
                else:
                    print "Account Creation Failed"
            else:
                print "Account Creation Failed"
        elif "exit" in input.lower():
            sock.close()
            sys.exit()
        else:
            print "Invalid Command: Try help for list of commands."
    
    prompt()

