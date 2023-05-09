from scapy.layers.inet import *
from scapy.all import *
import random
import subprocess
import time
import sys

#**************************MANUALLY CONFIGURE THIS PARAMETER**************************
PATHConf = r'C:\Users\UserName\Desktop\Sender\Configuration\ ' #MANUALLY CHANGE THIS to reflect the location of the "Configuration" folder included with the Sender's code. Path must end with \ followed by a blank space, which is automatically trimmed in the next line of code.
PATHConf = PATHConf[:-1] #Python strings can't terminate with "\" so the configuration path terminates with a white space that gets truncated immediatly

#Buffer variables for values read from configuration files
Secret_Message = "" 
Covert_Receiver_Address = ""
PORT = 0

IP_FLAGS = 2 #Default value assigned to the IP flags field, based on sampling of SYN packets in regular network traffic
IP_TTL = 64 #Default value assigned to TTL, based on windows default settings
IP_TOS = 0 #Default value assigned to IP TOS, based on sampling of packets belonging to regular network traffic
IP_ID = random.randrange(65536) #Random value assigned to IP Identification. The following values will be obtained by adding +1 every time
IP_OPTIONS = [] #Default value assigned to IP Options, based on sampling of packets belonging to regular network traffic
TCP_SPORT = 1025 #Declaration of the variable associated to Source Port. The value 1025 is actually never used and always overwritten at some point
TCP_OPTIONS = [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')] #Default value assigned to TCP Options, based on sampling of packets belonging to regular network traffic
TCP_WINDOW = 64240 #Default value assigned to TCP Window, based on sampling of packets belonging to regular network traffic
TCP_MSS = 1460
TCP_DYNAMIC_PORT_RANGE_START_PORT = 1024 #Default value assigned to dynamic port range start port, based on windows default settings
TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS = 64511 #Default value assigned to dynamic port range number of ports, based on windows default settings

LOOPBACK_ADDRESS = "127.0.0.1"
LOOPBACK_INTERFACE_NAME = "" #Name of the loopback interface used on the sender's host
Covert_Sender_Address = "" #IP Address used by the Sender. Must be chosen among its active and connected interfaces.
Layer2_Interface = "" #name of the layer 2 interface used by the sender on its local network (can be discovered with scapy's conf.ifaces.show() command)
Layer2_Source_Address = "" #mac address that identifies the sender's interface on its local network. Can be discovered using Windows' "ipconfig" command
Layer2_Destination_Address = "" #mac address that identifies the gateway on the sender's local network. Can be discovered using Windows' "arp -a" command
Layer2_Type = 2048 #value of the "type" field in layer 2 (2048 identifies the frame as "ipv4")

interfaceChoices = [] #buffer variable to keep track of potential interfaces to use for the transmission
interfaceInUse = -1 #counter that keeps track of what interface was chosen for the transmission

#Dictionary that defines various possible errors
Error = { 
    "NoError" : 1,
    "Termination0" : 0,
    "Termination1" : -1 ,
    "Termination2" : -2,
    "Termination3" : -3,
    "FourInvalidChars" : -4,
    "MessageCompromised" : -5
}

#Dictionary that defines error correction codes
ErrorCorrection = { 
    "DeleteSeparator" : 4026531840,       #1111 0000000 0000000 0000000 0000000 delete last transmission separator
    "DeleteSeparatorAnd1" : 4026531841,   #1111 0000000 0000000 0000000 0000001 delete last transmission separator and 1 character
    "DeleteSeparatorAnd2" : 4026531842,   #1111 0000000 0000000 0000000 0000010 delete last transmission separator and 2 characters
    "DeleteSeparatorAnd3" : 4026531843,   #1111 0000000 0000000 0000000 0000011 delete last transmission separator and 3 characters
    "Delete4Char" : 4026531844,           #1111 0000000 0000000 0000000 0000100 delete last four characters
    "FatalError" : 4026531845             #1111 0000000 0000000 0000000 0000101 fatal error
}

#STATE FLAGS
captureSuccessful = False #Global flag used to signal whether the capture of the source port was successful or not
receivedRST = False #Global flag used to signal whether the Covert Received sent a RST answer to our transmission or not
abortOperations = False #Global flag used to abort transmission in case something wrong is detected. Examples include the warden altering the secret message or failure in delivering a correction
lastError = Error["NoError"] #Global flag used to keep track of the last error that occurred
dataCorrupted = Error["NoError"] #variable that keeps track of possible errors
correctlyDelivered = False #variable that keeps track of whether the packet was correctly delivered
reachedHost = True #variable that keeps track of whether the receiver has sent any RST answer at all

#List of time intervals used by the sender to modulate its wait periods between transmissions. For more erratic intervals, instead of [1] use the list that is currently commented out
WaitVector = [1]
'''[10.58, 3.2295425128936768, 0.47, 
              10.3, 3.2295425128936768, 0.1, 10.5, 3.2295425128936768, 
              10.7, 3.2295425128936768, 0.1, 10.1, 3.2295425128936768, 
              10.23, 3.018668165206909, 0.1, 10.4, 3.2295425128936768,
              10.8, 3.2295425128936768, 0.1, 10.9, 3.2295425128936768, 
              10.22, 3.2295425128936768, 0.1, 10.67, 3.2295425128936768, 
              10.2, 3.018668165206909, 0.1, 10.45, 3.2295425128936768,
              10.1, 3.2295425128936768, 10.33, 3.2295425128936768]''' 
waitCounter = 0 #Counter used to navigate the interval list

#this function scouts scapy's routing table in order to find interfaces that can be viable candidates for a transmission (i.e. can reach the outer internet)
def refreshRoutes():
    global interfaceChoices
    interfaceChoices = []
    global interfaceInUse
    interfaceInUse = -1
    conf.auto_crop_tables = False
    routeList = repr(conf.route)
    rows = routeList.split("\n") #split route table into rows
    counter = 1 #navigation counter starts from 1 to skip the header row
    while (counter < len(rows)): #search in each row
        currentRow = rows[counter]
        currentRow = currentRow.split(" ") #current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        if (token=="0.0.0.0"): #we scout all information related to a route that allows us to reach the outer internet
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            interfaceGateway = token
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            interfaceName = ""
            while (token!=""):
                interfaceName = interfaceName + token + " " #catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name 
                token = currentRow.pop(0)
            interfaceName = interfaceName[:-1] #After concatenating each substring a " " is always added at the end. The final one however must me truncated
            while (token==""):
                token = currentRow.pop(0)
            interfaceIP = token
            interfaceChoices.append([interfaceIP, interfaceName, interfaceGateway]) #all information is then saved as a viable candidate in the interface list
        elif (token==LOOPBACK_ADDRESS): #if the network address of a row matches the loopback interface address we scout the loopback interface's name
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while (token==""):
                token = currentRow.pop(0)
            interfaceName = ""
            while (token!=""):
                interfaceName = interfaceName + token + " " #catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name 
                token = currentRow.pop(0)
            interfaceName = interfaceName[:-1] #After concatenating each substring a " " is always added at the end. The final one however must me truncated
            global LOOPBACK_INTERFACE_NAME
            LOOPBACK_INTERFACE_NAME = interfaceName
        counter = counter + 1

#this function scouts libpcap's interface list in order to fetch the numerical index of each interface. It also scouts the name of the loopback interface
def addInterfaceIndex():
    global interfaceChoices
    conf.auto_crop_tables = False
    interfaceList = str(conf.ifaces)
    rows = interfaceList.split("\n") #split route table into rows
    counter = 1 #navigation counter starts from 1 to skip the header row
    while (counter < len(rows)): #search in each row
        currentRow = rows[counter]
        currentRow = currentRow.split(" ") #current row is split into substrings using " " as separator
        if (len(currentRow)>0):
            token = currentRow.pop(0) #skip first word (libpcap)
        if (len(currentRow)>0):
            token = currentRow.pop(0)
        while (len(currentRow) > 0 and token==''): #skip empty space
            token = currentRow.pop(0)
        interfaceIndex = token #grab interface index
        if (len(currentRow)>0):
            token = currentRow.pop(0)
        while (len(currentRow) > 0 and token==''): #skip empty space
            token = currentRow.pop(0)
        rowInterfaceName = ""
        while (len(currentRow) > 0 and token!=''):
                rowInterfaceName = rowInterfaceName + token + " " #catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name 
                token = currentRow.pop(0)
        rowInterfaceName = rowInterfaceName[:-2] #After concatenating each substring a " " is always added at the end. The final one however must me truncated. We also truncate the last character as it may be a "_" in case name is too long
        while (len(currentRow) > 0 and token==""): #skip empty space
            token = currentRow.pop(0)
        if (len(currentRow)>0):
            token = currentRow.pop(0) #skip mac address
        while (len(currentRow) > 0 and token==""): #skip empty space
            token = currentRow.pop(0)
        rowIP = token #grab IP
        for candidate in interfaceChoices:
            if (candidate[0]==rowIP and (rowInterfaceName in candidate[1])):
                candidate.append(interfaceIndex)
        counter = counter + 1

#this function uses the Windows "netsh int ipv4 show interfaces" command to find out what interfaces among the ones chosen as potential candidates is effectively connected
#The first positive match is elected as the interface to use for the whole transmission
def chooseInterface():
    global interfaceInUse
    global Covert_Sender_Address
    global Layer2_Interface
    command = "powershell.exe netsh int ipv4 show interfaces"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False) #command is invoked in subprocess
    connectionInfo = ((process.communicate())[0]).decode("utf-8") #command output is formatted into utf-8 string
    candidateCounter = 0
    while (candidateCounter < len(interfaceChoices) and interfaceInUse==-1):
        rows = connectionInfo.split("\n")
        counter = 3
        while (counter < len(rows) and interfaceInUse==-1):
            currentRow = rows[counter]
            currentRow = currentRow.split(" ") #current row is split into substrings using " " as separator
            token = currentRow.pop(0)
            while (len(currentRow) > 0 and token==''): #skip empty spaces at the row start
                    token = currentRow.pop(0)
            if (token == (interfaceChoices[candidateCounter])[3]): #only check row if interface index matches
                token = currentRow.pop(0)
                while (len(currentRow) > 0 and token==''): #skip empty space
                    token = currentRow.pop(0)
                token = currentRow.pop(0) #skip Met.
                while (len(currentRow) > 0 and token==''): #skip empty space
                    token = currentRow.pop(0)
                token = currentRow.pop(0) #skip MTU
                while (len(currentRow) > 0 and token==''): #skip empty space
                    token = currentRow.pop(0)
                if (token=="connected"):
                    interfaceInUse = candidateCounter
                    Covert_Sender_Address = (interfaceChoices[candidateCounter])[0]
                    Layer2_Interface = (interfaceChoices[candidateCounter])[1]
                    return
            counter = counter + 1
        candidateCounter = candidateCounter + 1
    if interfaceInUse==-1:
        global abortOperations
        abortOperations = True
        print("errore chooseInterface")
        Layer2_Interface = "error"
        Covert_Sender_Address = "error"

#this function proceeds to fetch the MAC address of the interface selected for the transmission, using the Windows command "ipconfig /all"
def fetchEtherSRC():
    global Layer2_Source_Address
    global Layer2_Interface
    command = "powershell.exe ipconfig /all"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False) #command is invoked in subprocess
    connectionInfo = ((process.communicate())[0]).decode("utf-8", errors='ignore') #command output is formatted into utf-8 string
    connectionInfo = connectionInfo.replace("\r",'')
    rows = connectionInfo.split("\n")
    nameCounter = 0
    namePrefix = ""
    exit = False
    while (not exit and nameCounter<len(Layer2_Interface)):
        if (Layer2_Interface[nameCounter]!=" " and Layer2_Interface[nameCounter]!="." and Layer2_Interface[nameCounter]!=":"):
            exit = True
        else:
            namePrefix.append(Layer2_Interface[nameCounter])
        nameCounter = nameCounter + 1
    counter = 0
    while (counter < len(rows)):
        currentRow = rows[counter]
        currentRow = currentRow.split(" ") #current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        while (len(currentRow) > 0 and token==''): #skip empty space
            token = currentRow.pop(0)
        while (len(currentRow) > 0 and token!='.'): #skip row description
            token = currentRow.pop(0)
        while (len(currentRow) > 0 and token=='.' or token==':'): #skip empty space
            token = currentRow.pop(0)
        nameInRow = namePrefix
        while (len(currentRow) > 0 and token!=''):
            nameInRow = nameInRow + token + " " #catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name 
            token = currentRow.pop(0)
        nameInRow = nameInRow + token
        if (nameInRow==Layer2_Interface):
            nextRow = rows[counter+1].split(" ")
            EtherSRC = nextRow[len(nextRow)-1]
            Layer2_Source_Address = ""
            for i in range(0,len(EtherSRC)):
                if (i==2 or i==5 or i==8 or i==11 or i==14):
                    Layer2_Source_Address = Layer2_Source_Address + ":"
                else:
                    Layer2_Source_Address = Layer2_Source_Address + EtherSRC[i].lower()
            return
        counter = counter + 1
    global abortOperations
    Layer2_Source_Address = "error"
    abortOperations = True
    print("errore fetchEtherSRC")

#this function proceeds to fetch the MAC address of the default gateway associated with the interface selected for the transmission, using the Windows command "arp -a"
def fetchEtherDST():
    global Layer2_Destination_Address
    command = "arp -a -n " + (interfaceChoices[interfaceInUse])[0]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False) #command is invoked in subprocess
    arpTable = ((process.communicate())[0]).decode("utf-8", errors='ignore') #command output is formatted into utf-8 string
    arpTable = arpTable.replace("\r",'')
    rows = arpTable.split("\n")
    counter = 3
    while (counter < len(rows)):
        currentRow = rows[counter]
        currentRow = currentRow.split(" ") #current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        while (len(currentRow) > 0 and token==''): #skip empty space
            token = currentRow.pop(0)
        if (token==(interfaceChoices[interfaceInUse])[2]):
            token = currentRow.pop(0)
            while (len(currentRow) > 0 and token==''): #skip empty space
                token = currentRow.pop(0)
            Layer2_Destination_Address = ""
            for i in range(0,len(token)):
                if (i==2 or i==5 or i==8 or i==11 or i==14):
                    Layer2_Destination_Address = Layer2_Destination_Address + ":"
                else:
                    Layer2_Destination_Address = Layer2_Destination_Address + token[i]
            return
        else:
            counter = counter + 1
    global abortOperations
    abortOperations = True
    Layer2_Destination_Address = "error"
    print("errore fetchEtherDST")

#This function is a string parser specifically tailored to filter the output of the Windows command Get-NetTCPSetting -Setting Internet
#Accepts as input the command's output (tcpSettings) and a specific field to look for (key). Returns the field's value (if found) or "fail" if not found or exception occurs 
def tcpSettingsStringParser(tcpSettings, key ):
    try:
        tcpSettings = tcpSettings.replace("\r",'') #eliminate \r from the original string
        rows = tcpSettings.split("\n") #spit the output in rows
        counter = 0
        while (counter < len(rows)): #for each row
            currentRow = rows[counter]
            currentRow = currentRow.split(" ") #split the row into substrings using " " as separator
            token = currentRow.pop(0) 
            while ( len(currentRow) > 0 and (token != key) ): #navigate the row untill a token matches the input key
                token = currentRow.pop(0)
            if ( len(currentRow) > 0): #if a match is found before the row ends, the value we're looking for is the first token found to the right after "    :"
                token = currentRow.pop(0)
                while (token=="" or token==":"):
                    token = currentRow.pop(0)
                if ( token.isdigit() ): #before returning a value we make sure what we found is actually an integer
                    return token
            else:
                counter = counter + 1 #if a match is not found we advance the counter to look for the key in the next row
        return "fail"
    except:
        return "fail"

#this function invokes the Get-NetTCPSetting -Setting Internet command in a subprocess and catches its output in a string.
#It then passes the string to the string parser and stores each retrieved value in the corresponding global variable associated to the specific setting
def scoutTCPSettings():
    try:
        global TCP_DYNAMIC_PORT_RANGE_START_PORT
        global TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS
        command = "powershell.exe Get-NetTCPSetting -Setting Internet"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False) #command is invoked in subprocess
        tcpSettings = ((process.communicate())[0]).decode("utf-8") #command output is formatted into utf-8 string
        scoutedDynamicPortRangeStartPort = tcpSettingsStringParser(tcpSettings, "DynamicPortRangeStartPort")
        if (scoutedDynamicPortRangeStartPort!="fail"):
            TCP_DYNAMIC_PORT_RANGE_START_PORT = int(scoutedDynamicPortRangeStartPort)
        scoutedDynamicPortRangeNumberOfPorts = tcpSettingsStringParser(tcpSettings, "DynamicPortRangeNumberOfPorts")
        if (scoutedDynamicPortRangeNumberOfPorts!="fail"):
            TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS = int(scoutedDynamicPortRangeNumberOfPorts)
    except:
        ()

#This function signals the arrival of a RST answer on part of the receiver by changing the value of a global flag.
#Accepts as input the packet sent from the receiver and optionally the original packet sent by the sender. If such a packet is provided, the function compares its data with the answer's signature to make sure it wasn't altered during its travel
def processAnswer(receiverAnswer,originalPacket,Ntransmissions):
    print("--RECEIVED ANSWER--")
    global receivedRST
    receivedRST = True
    if (originalPacket!=None and Ntransmissions==0):
        random.seed(originalPacket[IP].seq + originalPacket[IP].id)
        expectedID = int(random.random()*(2**16))
        if receiverAnswer[IP].id != expectedID:
            print("*****      *****      SABOTAGE ALERT     *****      *****")
            global abortOperations
            abortOperations = True

#this function uses scapy's sniff method to listen for the receiver's answer to a packet sent by the sender
#accepts as input a filter rule and a maximum timeout and passes them both to the sniff method. Can also accept the original packet sent from the sender: if present, it will be passed to the processAnswer callback function.
def listenForRST(filterMaskRst, delay, originalPacket=None, Ntransmissions=-1):
    print("waiting answer")
    global receivedRST
    receivedRST = False #before sniffing, these global flags are set to "False"
    sniff(iface=Layer2_Interface, filter=filterMaskRst, count = 1, timeout=delay, prn = lambda receiverAnswer : processAnswer(receiverAnswer,originalPacket,Ntransmissions)) #if the sniff is successful, the processAnswer() callback sets the flag to "True"
    print("wait finished")
    return receivedRST

def captureSourcePort(p):
    global captureSuccessful
    try:
        global IP_TOS
        global TCP_SPORT
        global IP_FLAGS
        global IP_TTL
        global IP_OPTIONS
        global TCP_OPTIONS
        global TCP_WINDOW
        TCP_SPORT = p[TCP].sport
        IP_FLAGS = p[IP].flags
        IP_TTL = p[IP].ttl
        IP_OPTIONS = p[IP].options
        IP_TOS = p[IP].tos
        TCP_WINDOW = p[TCP].window
        TOpt = p[TCP].options
        if ((TOpt[0])[0] == 'MSS'): #the MSS value used in sockets opened on the loopback interface does not correctly reflect the one used in other interfaces and shall thus be rewritten
            (TOpt[0])[1] = TCP_MSS
        TCP_OPTIONS = TOpt #every other TCP option on the other hand remains the same regardless of the specific interface used
        captureSuccessful = True #in case of success the function also updates this flag's value to "True"
    except:
        captureSuccessful = False

#this function launches a secondary script in a subprocess in order to create an authentic socket on the loopback interface after a certain delay
#the function then uses scapy's sniff method to intercept the first SYN packet and extract relevant information from it (SourcePortOnly is set to "True" if the only information needed is the Source Port Number)
def scoutSourcePort():
    global captureSuccessful
    try:
        captureSuccessful = False #before attempting a capture, the global flag is set to "False". If the capture is successful, the callback function passed to scapy's sniff method will set it back to "True"
        filterMaskExtraData = "ip && tcp && src host "+LOOPBACK_ADDRESS+" && dst host "+LOOPBACK_ADDRESS+" && tcp[13]==2" #filter passed to the sniff method: the only relevant packets are tcp/ip packet with source and destination address set to "127.0.0.1" and the SYN flag set to 1
        selfSocket = [ 'python' , 'SpawnSocket.py', LOOPBACK_ADDRESS, str(PORT), str(0.05) ]
        subprocess.Popen(selfSocket, shell=False)
        sniff(iface=LOOPBACK_INTERFACE_NAME, filter=filterMaskExtraData, prn = lambda x : captureSourcePort(x), count = 1, timeout=0.5)
    except:
        captureSuccessful = False
    return captureSuccessful

#This function is invoked when a message received by mistake by the Covert Receiver has triggered unwanted behaviour and is used to identify the error's nature
#Accepts the message as input, returns an integer representing a specific error
def identifyError(message):
    termPosition = message // (2**28)
    message = message % (2**28)
    if message == ErrorCorrection["FatalError"] or message == ErrorCorrection["Delete4Char"] or message == ErrorCorrection["DeleteSeparator"] or message == ErrorCorrection["DeleteSeparatorAnd1"] or message == ErrorCorrection["DeleteSeparatorAnd2"] or message == ErrorCorrection["DeleteSeparatorAnd3"]:
        return Error["MessageCompromised"] #fatal error: the covert receiver has mistakenly received an error code and deleted part of the transmission when it was not supposed to
    separator = 21
    totalChar = 0
    while separator>=0 :
        next = message // (2**separator)
        if (totalChar+1)==termPosition and next == 4:
            TerminationError = "Termination" + str(totalChar)
            return Error[TerminationError] #termination error: the covert receiver has mistakenly received a certain number of invalid characters followed by the "termination" character
        message = message % (2**separator)
        separator = separator - 7
        totalChar = totalChar + 1
    return Error["FourInvalidChars"] #four characters error: the covert receiver has mistakenly received four invalid characters

#This function accepts as input a raw ISN, an IP Identification value and the Covert Receiver's address. It then proceeds to masquerade the sequence number to conceal the hidden message
def encryptISN(rawISN, IDValue, Covert_Receiver_Address):
    IPbytes = Covert_Receiver_Address.split(".") #the receiver address is separated using "." to obtain its individual bytes
    random.seed(IDValue*(2**16) + int(IPbytes[2])*(2**8) + int(IPbytes[3])) #the IP Identification value together with the last two bytes of the Receiver's address are used as a seed for python's PRNG function
    return rawISN^(int(random.random()*(2**32))) #The output of PRNG is then combined with the raw ISN with a XOR operation

conf.sniff_promisc = 0 #disable promiscous mode in scapy
with open(PATHConf+"Message.txt","r") as f:
    Secret_Message = f.read() #read secret message from configuration files
if len(Secret_Message)==0:
    sys.exit() #if no secret message is read, terminate program
else:
    print ("message length: " + str(len(Secret_Message)))
    Secret_Message = Secret_Message + (chr(4)) #if a secret message is read, append the "termination character" to it (this character is EOT in ASCII)
with open(PATHConf+"CovertReceiverAddress.txt","r") as f:
    Covert_Receiver_Address = f.read() #read receiver address from configuration files
with open(PATHConf+"Port.txt","r") as f:
    PORT = int(f.read()) #read destination port from configuration files
refreshRoutes() #fetch potential candidates among interfaces capable of reaching the outer internet
addInterfaceIndex() #assign index to each candidate
chooseInterface() #choose the first valid candidate that also has a currently active connection
fetchEtherSRC() #fetch mac address of the chosen interface
fetchEtherDST() #fetch mac address of the default gateway used by the chosen interface
scoutTCPSettings() #discover the tcp settings on this host
print("Covert sender address: " + Covert_Sender_Address)
print("Covert receiver address: " + Covert_Receiver_Address)
print("Transmission Interface: " + Layer2_Interface)
print("Transmission Interface MAC Address: " + Layer2_Source_Address)
print("Transmission Gateway MAC Address: " + Layer2_Destination_Address)
filterMask = "ip && tcp && dst host " + Covert_Receiver_Address + " && (tcp[13] & 1!=0 )" #filter option for the sniff method when listening for the outgoing FIN packet
filterMaskRst = "ip && tcp && src host "+Covert_Receiver_Address+" && dst host "+Covert_Sender_Address+" && tcp[13]==20" #filter used by scapy's sniff method upon listening for the Receiver's RST answer
TCP_SPORT = random.randrange(TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS) + TCP_DYNAMIC_PORT_RANGE_START_PORT + 1 #assign a default value to Source Port (based on dynamic port range discovered in the step before). It will only be used if "Source Port Reservation" fails somehow
rawISNs = [] #Prepare list containing raw ISNs values to use in forged packets
while (len(Secret_Message)!=0): #parse the secret message string and create a list of raw sequence numbers containing its characters
    if (len(Secret_Message)>4): #since sequence numbers are 32 bits long and an ASCII character is 7 bits long, a total of four ASCII character can fit in a single raw ISN
        characterOne = ord(Secret_Message[0])
        characterTwo = ord(Secret_Message[1])
        characterThree = ord(Secret_Message[2])
        characterFour = ord(Secret_Message[3])
        Secret_Message = Secret_Message[4:] #after the four characters are stored in a raw ISN, they are also eliminated from the string
        ISN = (characterOne * (2**21)) + (characterTwo * (2**14)) + (characterThree * (2**7)) + (characterFour)
        rawISNs.append(ISN) #the four characters are stored in the 28 less significant bits of the raw ISN. The four starting bits are always random.
    else: #if four or less characters are left in the secret message string, they are instead copied one at the time. Any free space remaining on the right is padded with 0
        ISN = 0
        counter = 4
        while (len(Secret_Message)!=0):
            nextChar = ord(Secret_Message[0])
            Secret_Message = Secret_Message[1:]
            ISN = ISN * (2**7) + nextChar
            counter = counter - 1
        termPosition = 4 - counter #the ISN that contains the EOT character must also include a label in its 4 most significant bits to allow the receiver to recognize it
        termPosition = termPosition*(2**28)
        ISN = ISN * (2**(7*counter)) + termPosition
        rawISNs.append(ISN)
ForgedPacket = Ether()/IP()/TCP() #create the packet
ForgedPacket[Ether].src = Layer2_Source_Address
ForgedPacket[Ether].dst = Layer2_Destination_Address
ForgedPacket[Ether].type = Layer2_Type
ForgedPacket[IP].dst = Covert_Receiver_Address #assign destination address
ForgedPacket[IP].src = Covert_Sender_Address #assign sender address
ForgedPacket[TCP].dport = PORT #assign destination port
ForgedPacket[TCP].flags = 2 #SYN flag is set to 1
lastISN = -1
nextISN = lastISN #buffer variable used to store the processed sequence number that will be assigned to the forged packet
IDValue = IP_ID
TS_interval_separator = 0
FirstPacket = True
initialTime = time.time()

while (len(rawISNs)!=0 and reachedHost and not abortOperations): #while there are still raw ISNs to transmit

    print(str(len(rawISNs)) + " more isn to go")
    nextRawISN = rawISNs.pop(0) #get next ISN to transmit
    nextISN = lastISN
    while (nextISN==lastISN):
        IDValue = (IDValue + 1)%(2**16)
        nextISN = encryptISN(nextRawISN, IDValue, Covert_Receiver_Address) #obtain a processed sequence number value
    lastISN = nextISN
    ForgedPacket[TCP].seq = nextISN #assign new processed sequence number and new id value
    ForgedPacket[IP].id =  IDValue
    scoutedPort = scoutSourcePort()
    if not scoutedPort: #reserve a new source port
        TCP_SPORT = (TCP_SPORT + 1)%(2**16)
        if TCP_SPORT == 0:
            TCP_SPORT = TCP_DYNAMIC_PORT_RANGE_START_PORT + 1
    ForgedPacket[TCP].sport = TCP_SPORT
    ForgedPacket[IP].tos = IP_TOS #IP Terms of service
    ForgedPacket[IP].flags = IP_FLAGS #IP Flags
    ForgedPacket[IP].ttl = IP_TTL #IP Time to leave
    ForgedPacket[IP].options = IP_OPTIONS #IP Options
    ForgedPacket[TCP].window = TCP_WINDOW #TCP Window size
    ForgedPacket[TCP].options = TCP_OPTIONS #TCP Options
    del ForgedPacket[IP].chksum
    del ForgedPacket[TCP].chksum
    ForgedPacket = ForgedPacket.__class__(bytes(ForgedPacket)) #The computation of fields such as IP Initial Header Length, TCP Data offset and Checksums is delegated to scapy
    correctlyDelivered = False #variable that keeps track of whether the packet was correctly delivered
    dataCorrupted = Error["NoError"] #variable that keeps track of possible errors
    reachedHost = False #variable that keeps track of whether the receiver has sent any RST answer at all

    if not FirstPacket:
        NEXT_WAIT = WaitVector[waitCounter]
        waitCounter = (waitCounter + 1)%(len(WaitVector))
        NEXT_WAIT = NEXT_WAIT + random.random()*(1/100)
        elapsed = time.time() - TS_interval_separator #before transmitting, be sure to finish waiting the transmission interval
        if (NEXT_WAIT - elapsed > 0): 
            time.sleep(NEXT_WAIT - elapsed)
    
    FirstPacket = False
    TS_interval_separator = time.time() #reset the interval separator right before each transmission

    sendp(ForgedPacket, iface=Layer2_Interface, verbose=False)
    if listenForRST(filterMaskRst, 2, ForgedPacket, 0): #listen for a reply using scapy's sniff method
        reachedHost = True #if the receiver answers, this variable signals it was possible to reach it
        correctlyDelivered = True #if the message is correctly delivered, the receiver will automatically ignore any future packet that hasn't changed its sequence number (thus eliminating the risk of errors)

    IDValue = (IDValue + 1)%(2**16) #after each transmission, the packet used in the next transmission is prepared
    ForgedPacket[IP].id = IDValue #the packet is assigned a new IDValue
    del ForgedPacket[IP].chksum #the checksum is deleted and then recomputed
    ForgedPacket = ForgedPacket.__class__(bytes(ForgedPacket))

    NEXT_WAIT = WaitVector[waitCounter]
    waitCounter = (waitCounter + 1)%(len(WaitVector))
    NEXT_WAIT = NEXT_WAIT + random.random()*(1/100)
    elapsed = time.time() - TS_interval_separator #before transmitting, be sure to finish waiting the transmission interval
    if (NEXT_WAIT - elapsed > 0): 
        time.sleep(NEXT_WAIT - elapsed)
        
    TS_interval_separator = time.time()

    sendp(ForgedPacket, iface=Layer2_Interface, verbose=False) #Second attempt
    if listenForRST(filterMaskRst, 2, ForgedPacket, 1):
        reachedHost = True
        if not correctlyDelivered:
            message = encryptISN(ForgedPacket[TCP].seq, ForgedPacket[IP].id, ForgedPacket[IP].dst)
            dataCorrupted = identifyError(message)

    if not reachedHost or nextRawISN==4026531845: #if the receiver was unreachable or we just signaled a "fatal error", transmission must stop
        abortOperations = True

    if not correctlyDelivered: #if the message was not correctly delivered
        rawISNs.insert(0, nextRawISN) #reinsert last raw ISN so a new attempt at transmitting it is made
        if dataCorrupted==Error["Termination0"]: #if an error occurred, also insert a special ISN aimed at correcting the error
            rawISNs.insert(0, ErrorCorrection["DeleteSeparator"])
        elif dataCorrupted==Error["Termination1"]:
            rawISNs.insert(0, ErrorCorrection["DeleteSeparatorAnd1"])
        elif dataCorrupted==Error["Termination2"]:
            rawISNs.insert(0, ErrorCorrection["DeleteSeparatorAnd2"])
        elif dataCorrupted==Error["Termination3"]:
            rawISNs.insert(0, ErrorCorrection["DeleteSeparatorAnd3"])
        elif dataCorrupted==Error["FourInvalidChars"]:
            rawISNs.insert(0, ErrorCorrection["Delete4Char"])
        elif dataCorrupted==Error["MessageCompromised"]:
            rawISNs.insert(0, ErrorCorrection["FatalError"])
        if lastError == Error["NoError"]: #the first error that occurs can be tolerated, but we must keep in mind it happened
            lastError = dataCorrupted
        else: #two errors in a row are not acceptable because sending multiple corrections might cause the receiver to cancel part of the message
            abortOperations = True #if an error already took place in the former transmission, the program stops
    else: #if the message arrives correctly, we reset the error count
        lastError = Error["NoError"]
    print("*****Correctly delivered: "+str(correctlyDelivered)+" *****Error code: " + str(lastError) + " *****Reached host: " + str(reachedHost) + " *****Abort: " + str(abortOperations) + " *****")

finishTime = time.time() - initialTime
print("Finished! Total transmission time: " + str(finishTime) + " seconds, or: " + str(math.floor(finishTime/60)) + " minutes and " + str(finishTime%60) + " seconds.")