import json
import math
import os
import random
import subprocess
import sys
import time

from scapy.all import *
from scapy.layers.inet import *

# Path to the Configuration folder, where Secret Message to send, Covert Receiver Address and Port are stored
pathConf = os.path.join(os.getcwd(), 'transmission_config.json')

# Dictionary that defines various possible errors
error = {
    "NoError" : 1,
    "Termination0" : 0,
    "Termination1" : -1 ,
    "Termination2" : -2,
    "Termination3" : -3,
    "FourInvalidChars" : -4,
    "MessageCompromised" : -5
}

# Dictionary that defines error correction codes
errorCorrection = {
    "DeleteSeparator" : 4026531840,       # 1111 0000000 0000000 0000000 0000000 delete last transmission separator
    "DeleteSeparatorAnd1" : 4026531841,   # 1111 0000000 0000000 0000000 0000001 delete last transmission separator and 1 character
    "DeleteSeparatorAnd2" : 4026531842,   # 1111 0000000 0000000 0000000 0000010 delete last transmission separator and 2 characters
    "DeleteSeparatorAnd3" : 4026531843,   # 1111 0000000 0000000 0000000 0000011 delete last transmission separator and 3 characters
    "Delete4Char" : 4026531844,           # 1111 0000000 0000000 0000000 0000100 delete last four characters
    "FatalError" : 4026531845             # 1111 0000000 0000000 0000000 0000101 fatal error
}

TCPFieldsValues = {
    "IP_FLAGS" : 2,  # Default value assigned to the IP flags field, based on sampling of SYN packets in regular network traffic
    "IP_TTL" : 64,  # Default value assigned to TTL, based on windows default settings
    "IP_TOS" : 0,  # Default value assigned to IP TOS, based on sampling of packets belonging to regular network traffic
    "IP_ID" : random.randrange(65536),  # Random value assigned to IP Identification. The following values will be obtained by adding +1 every time
    "IP_OPTIONS" : [],  # Default value assigned to IP Options, based on sampling of packets belonging to regular network traffic
    "TCP_SPORT" : 1025,  # Declaration of the variable associated to Source Port. The value 1025 is actually never used and always overwritten at some point
    "TCP_OPTIONS" : [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')],  # Default value assigned to TCP Options, based on sampling of packets belonging to regular network traffic
    "TCP_WINDOW" : 64240,  # Default value assigned to TCP Window, based on sampling of packets belonging to regular network traffic
    "TCP_MSS" : 1460,
    "TCP_DYNAMIC_PORT_RANGE_START_PORT" : 1024,  # Default value assigned to dynamic port range start port, based on windows default settings
    "TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS" : 64511  # Default value assigned to dynamic port range number of ports, based on windows default settings
}

interfaceInfo = {
    "LOOPBACK_ADDRESS" : "127.0.0.1",
    "LOOPBACK_INTERFACE_NAME" : "",  # Name of the loopback interface used on the sender's host
    "Covert_Sender_Address" : "",  # IP Address used by the Sender. Must be chosen among its active and connected interfaces.
    "Layer2_Interface" : "",  # name of the layer 2 interface used by the sender on its local network (can be discovered with scapy's conf.ifaces.show() command)
    "Layer2_Source_Address" : "",  # mac address that identifies the sender's interface on its local network. Can be discovered using Windows' "ipconfig" command
    "Layer2_Destination_Address" : "",  # mac address that identifies the gateway on the sender's local network. Can be discovered using Windows' "arp -a" command
    "Layer2_Type" : 2048,  # value of the "type" field in layer 2 (2048 identifies the frame as "ipv4")
    "interfaceChoices" : [],  # buffer variable to keep track of potential interfaces to use for the transmission
    "interfaceInUse" : -1  # counter that keeps track of what interface was chosen for the transmission
}

stateManager = {
    "captureSuccessful" : False,  # Global flag used to signal whether the capture of the source port was successful or not
    "receivedRST" : False,  # Global flag used to signal whether the Covert Received sent a RST answer to our transmission or not
    "abortOperations" : False,  # Global flag used to abort transmission in case something wrong is detected. Examples include the warden altering the secret message or failure in delivering a correction
    "formerTransmissionError" : error["NoError"],  # Global flag used to keep track of the last error that occurred
    "currentError" : error["NoError"],  # variable that keeps track of possible errors
    "correctlyDelivered" : False,  # variable that keeps track of whether the packet was correctly delivered
    "reachedHost" : True  # variable that keeps track of whether the receiver has sent any RST answer at all
}

# List of time intervals used by the sender to modulate its wait periods between transmissions. For more erratic intervals, instead of [1] use the list that is currently commented out
wait_parameters = {
    "list" : [1],  # list of time intervals to use between transmissions
    "counter" : 0  # counter used to navigate the interval list
}

'''[10.58, 3.2295425128936768, 0.47,
              10.3, 3.2295425128936768, 0.1, 10.5, 3.2295425128936768,
              10.7, 3.2295425128936768, 0.1, 10.1, 3.2295425128936768,
              10.23, 3.018668165206909, 0.1, 10.4, 3.2295425128936768,
              10.8, 3.2295425128936768, 0.1, 10.9, 3.2295425128936768,
              10.22, 3.2295425128936768, 0.1, 10.67, 3.2295425128936768,
              10.2, 3.018668165206909, 0.1, 10.45, 3.2295425128936768,
              10.1, 3.2295425128936768, 10.33, 3.2295425128936768]'''


# this function scouts scapy's routing table in order to find interfaces that can be viable candidates for a transmission (i.e. can reach the outer internet)
def refreshRoutes(interfaceInfo):
    interfaceInfo["interfaceChoices"] = []
    interfaceInfo["interfaceInUse"] = -1
    conf.auto_crop_tables = False
    routeList = repr(conf.route)
    rows = routeList.split("\n")  # split route table into rows
    counter = 1  # navigation counter starts from 1 to skip the header row
    while counter < len(rows):  # search in each row
        currentRow = rows[counter]
        currentRow = currentRow.split(" ")  # current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        if token == "0.0.0.0":  # we scout all information related to a route that allows us to reach the outer internet
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            interfaceGateway = token
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            interfaceName = ""
            while token != "":
                interfaceName = interfaceName + token + " "  # catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name
                token = currentRow.pop(0)
            interfaceName = interfaceName[:-1]  # After concatenating each substring a " " is always added at the end. The final one however must me truncated
            while token == "":
                token = currentRow.pop(0)
            interfaceIP = token
            interfaceInfo["interfaceChoices"].append(
                {
                    "ip" : interfaceIP,
                    "name" : interfaceName,
                    "gateway" : interfaceGateway
                }
            )  # all information is then saved as a viable candidate in the interface list
        elif token == interfaceInfo["LOOPBACK_ADDRESS"]:  # if the network address of a row matches the loopback interface address we scout the loopback interface's name
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            token = currentRow.pop(0)
            while token == "":
                token = currentRow.pop(0)
            interfaceName = ""
            while token != "":
                interfaceName = interfaceName + token + " "  # catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name
                token = currentRow.pop(0)
            interfaceName = interfaceName[:-1]  # After concatenating each substring a " " is always added at the end. The final one however must me truncated
            interfaceInfo["LOOPBACK_INTERFACE_NAME"] = interfaceName
        counter = counter + 1


# this function scouts libpcap's interface list in order to fetch the numerical index of each interface. It also scouts the name of the loopback interface
def addInterfaceIndex(interfaceInfo):
    conf.auto_crop_tables = False
    interfaceList = str(conf.ifaces)
    rows = interfaceList.split("\n")  # split route table into rows
    counter = 1  # navigation counter starts from 1 to skip the header row
    while counter < len(rows):  # search in each row
        currentRow = rows[counter]
        currentRow = currentRow.split(" ")  # current row is split into substrings using " " as separator
        if len(currentRow) > 0:
            token = currentRow.pop(0)  # skip first word (libpcap)
        if len(currentRow) > 0:
            token = currentRow.pop(0)
        while len(currentRow) > 0 and token == '':  # skip empty space
            token = currentRow.pop(0)
        interfaceIndex = token  # grab interface index
        if len(currentRow) > 0:
            token = currentRow.pop(0)
        while len(currentRow) > 0 and token == '':  # skip empty space
            token = currentRow.pop(0)
        rowInterfaceName = ""
        while len(currentRow) > 0 and token != '':
            rowInterfaceName = rowInterfaceName + token + " "  # catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name
            token = currentRow.pop(0)
        rowInterfaceName = rowInterfaceName[:-2]  # After concatenating each substring a " " is always added at the end. The final one however must me truncated. We also truncate the last character as it may be a "_" in case name is too long
        while len(currentRow) > 0 and token == "":  # skip empty space
            token = currentRow.pop(0)
        if len(currentRow) > 0:
            token = currentRow.pop(0)  # skip mac address
        while len(currentRow) > 0 and token == "":  # skip empty space
            token = currentRow.pop(0)
        rowIP = token  # grab IP
        for candidate in interfaceInfo["interfaceChoices"]:
            if candidate["ip"] == rowIP and (rowInterfaceName in candidate["name"]):
                candidate["index"] = interfaceIndex
        counter = counter + 1


# this function uses the Windows "netsh int ipv4 show interfaces" command to find out what interfaces among the ones chosen as potential candidates is effectively connected
# The first positive match is elected as the interface to use for the whole transmission
def chooseInterface(interfaceInfo, stateManager):
    command = "powershell.exe netsh int ipv4 show interfaces"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False)  # command is invoked in subprocess
    connectionInfo = ((process.communicate())[0]).decode("utf-8")  # command output is formatted into utf-8 string
    candidateCounter = 0
    while candidateCounter < len(interfaceInfo["interfaceChoices"]) and interfaceInfo["interfaceInUse"] == -1:
        rows = connectionInfo.split("\n")
        counter = 3
        while counter < len(rows) and interfaceInfo["interfaceInUse"] == -1:
            currentRow = rows[counter]
            currentRow = currentRow.split(" ")  # current row is split into substrings using " " as separator
            token = currentRow.pop(0)
            while len(currentRow) > 0 and token == '':  # skip empty spaces at the row start
                token = currentRow.pop(0)
            if token == ((interfaceInfo["interfaceChoices"])[candidateCounter])["index"]:  # only check row if interface index matches
                token = currentRow.pop(0)
                while len(currentRow) > 0 and token == '':  # skip empty space
                    token = currentRow.pop(0)
                token = currentRow.pop(0)  # skip Met.
                while len(currentRow) > 0 and token == '':  # skip empty space
                    token = currentRow.pop(0)
                token = currentRow.pop(0)  # skip MTU
                while len(currentRow) > 0 and token == '':  # skip empty space
                    token = currentRow.pop(0)
                if token == "connected":
                    interfaceInfo["interfaceInUse"] = candidateCounter
                    interfaceInfo["Covert_Sender_Address"] = ((interfaceInfo["interfaceChoices"])[candidateCounter])["ip"]
                    interfaceInfo["Layer2_Interface"] = ((interfaceInfo["interfaceChoices"])[candidateCounter])["name"]
                    return
            counter = counter + 1
        candidateCounter = candidateCounter + 1
    if interfaceInfo["interfaceInUse"] == -1:
        stateManager["abortOperations"] = True
        print("errore chooseInterface")
        interfaceInfo["Layer2_Interface"] = "error"
        interfaceInfo["Covert_Sender_Address"] = "error"


# this function proceeds to fetch the MAC address of the interface selected for the transmission, using the Windows command "ipconfig /all"
def fetchEtherSRC(interfaceInfo, stateManager):
    command = "powershell.exe ipconfig /all"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False)  # command is invoked in subprocess
    connectionInfo = ((process.communicate())[0]).decode("utf-8", errors='ignore')  # command output is formatted into utf-8 string
    connectionInfo = connectionInfo.replace("\r", '')
    rows = connectionInfo.split("\n")
    nameCounter = 0
    namePrefix = ""
    Layer2_Interface = interfaceInfo["Layer2_Interface"]
    exit = False
    while not exit and nameCounter < len(Layer2_Interface):
        if Layer2_Interface[nameCounter] not in [" ", ".", ":"]:
            exit = True
        else:
            namePrefix.append(Layer2_Interface[nameCounter])
        nameCounter = nameCounter + 1
    counter = 0
    while counter < len(rows):
        currentRow = rows[counter]
        currentRow = currentRow.split(" ")  # current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        while len(currentRow) > 0 and token == '':  # skip empty space
            token = currentRow.pop(0)
        while len(currentRow) > 0 and token != '.':  # skip row description
            token = currentRow.pop(0)
        while len(currentRow) > 0 and token == '.' or token == ':':  # skip empty space
            token = currentRow.pop(0)
        nameInRow = namePrefix
        while len(currentRow) > 0 and token != '':
            nameInRow = nameInRow + token + " "  # catch all substrings in the middle and reassemble them into a string that correctly represents an interface's name
            token = currentRow.pop(0)
        nameInRow = nameInRow + token
        if nameInRow == Layer2_Interface:
            nextRow = rows[counter+1].split(" ")
            EtherSRC = nextRow[len(nextRow)-1]
            interfaceInfo["Layer2_Source_Address"] = EtherSRC.replace("-", ":").lower()
            return
        counter = counter + 1
    stateManager["abortOperations"] = True
    interfaceInfo["Layer2_Source_Address"] = "error"
    print("errore fetchEtherSRC")


# this function proceeds to fetch the MAC address of the default gateway associated with the interface selected for the transmission, using the Windows command "arp -a"
def fetchEtherDST(interfaceInfo, stateManager):
    chosen_interface = interfaceInfo["interfaceInUse"]
    chosen_interface_ip = ((interfaceInfo["interfaceChoices"])[chosen_interface])["ip"]
    chosen_interface_gateway = ((interfaceInfo["interfaceChoices"])[chosen_interface])["gateway"]
    command = "arp -a -n " + chosen_interface_ip
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False)  # command is invoked in subprocess
    arpTable = ((process.communicate())[0]).decode("utf-8", errors='ignore')  # command output is formatted into utf-8 string
    arpTable = arpTable.replace("\r", '')
    rows = arpTable.split("\n")
    counter = 3  # navigation counter starts from 3 to skip the header rows
    while counter < len(rows):
        currentRow = rows[counter]
        currentRow = currentRow.split(" ")  # current row is split into substrings using " " as separator
        token = currentRow.pop(0)
        while len(currentRow) > 0 and token == '':  # skip empty space
            token = currentRow.pop(0)
        if token == chosen_interface_gateway:
            token = currentRow.pop(0)
            while len(currentRow) > 0 and token == '':  # skip empty space
                token = currentRow.pop(0)
            interfaceInfo["Layer2_Destination_Address"] = token.replace("-", ":").lower()
            return
        else:
            counter = counter + 1
    stateManager["abortOperations"] = True
    interfaceInfo["Layer2_Destination_Address"] = "error"
    print("errore fetchEtherDST")


# This function is a string parser specifically tailored to filter the output of the Windows command Get-NetTCPSetting -Setting Internet
# Accepts as input the command's output (tcpSettings) and a specific field to look for (key). Returns the field's value (if found) or "fail" if not found or exception occurs
def tcpSettingsStringParser(tcpSettings, key):
    try:
        tcpSettings = tcpSettings.replace("\r", '')  # eliminate \r from the original string
        rows = tcpSettings.split("\n")  # spit the output in rows
        counter = 0
        while counter < len(rows):  # for each row
            currentRow = rows[counter]
            currentRow = currentRow.split(" ")  # split the row into substrings using " " as separator
            token = currentRow.pop(0)
            while len(currentRow) > 0 and token != key:  # navigate the row untill a token matches the input key
                token = currentRow.pop(0)
            if len(currentRow) > 0:  # if a match is found before the row ends, the value we're looking for is the first token found to the right after "    :"
                token = currentRow.pop(0)
                while token == "" or token == ":":
                    token = currentRow.pop(0)
                if token.isdigit():  # before returning a value we make sure what we found is actually an integer
                    return token
            else:
                counter = counter + 1  # if a match is not found we advance the counter to look for the key in the next row
        return None
    except Exception:
        return None


# this function invokes the Get-NetTCPSetting -Setting Internet command in a subprocess and catches its output in a string.
# It then passes the string to the string parser and stores each retrieved value in the corresponding global variable associated to the specific setting
def scoutTCPSettings(TCPFieldsValues):
    try:
        command = "powershell.exe Get-NetTCPSetting -Setting Internet"
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=False)  # command is invoked in subprocess
        tcpSettings = ((process.communicate())[0]).decode("utf-8")  # command output is formatted into utf-8 string
        scoutedDynamicPortRangeStartPort = tcpSettingsStringParser(tcpSettings, "DynamicPortRangeStartPort")
        if scoutedDynamicPortRangeStartPort is not None:
            TCPFieldsValues["TCP_DYNAMIC_PORT_RANGE_START_PORT"] = int(scoutedDynamicPortRangeStartPort)
        scoutedDynamicPortRangeNumberOfPorts = tcpSettingsStringParser(tcpSettings, "DynamicPortRangeNumberOfPorts")
        if scoutedDynamicPortRangeNumberOfPorts is not None:
            TCPFieldsValues["TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS"] = int(scoutedDynamicPortRangeNumberOfPorts)
    except Exception:
        pass


# This function signals the arrival of a RST answer on part of the receiver by changing the value of a global flag.
# Accepts as input the packet sent from the receiver and the original packet sent by the sender.
# The function compares the original packet's data with the answer's signature to make sure it wasn't altered during its travel
def processAnswer(receiverAnswer, originalPacket, stateManager):
    print("--RECEIVED ANSWER--")
    stateManager["receivedRST"] = True
    random.seed(originalPacket[IP].seq + originalPacket[IP].id)
    expectedID = int(random.random()*(2**16))
    if receiverAnswer[IP].id != expectedID:
        print("*****      *****      SABOTAGE ALERT     *****      *****")
        stateManager["abortOperations"] = True


# this function uses scapy's sniff method to listen for the receiver's answer to a packet sent by the sender
# accepts as input a filter rule and a maximum timeout and passes them both to the sniff method. Can also accept the original packet sent from the sender: if present, it will be passed to the processAnswer callback function.
def listenForRST(filterMaskRst, delay, interfaceInfo, stateManager, originalPacket=None, Ntransmissions=-1):
    print("waiting answer")
    stateManager["receivedRST"] = False  # before sniffing, these global flags are set to "False"
    sniff(iface=interfaceInfo["Layer2_Interface"], filter=filterMaskRst, count=1, timeout=delay, prn=lambda receiverAnswer : processAnswer(receiverAnswer, originalPacket, stateManager))  # if the sniff is successful, the processAnswer() callback sets the flag to "True"
    print("wait finished")
    return stateManager["receivedRST"]


def captureSourcePort(p, TCPFieldsValues, stateManager):
    try:
        TCPFieldsValues["IP_FLAGS"] = p[IP].flags
        TCPFieldsValues["IP_TTL"] = p[IP].ttl
        TCPFieldsValues["IP_OPTIONS"] = p[IP].options
        TCPFieldsValues["IP_TOS"] = p[IP].tos
        TCPFieldsValues["TCP_WINDOW"] = p[TCP].window
        TCPFieldsValues["TCP_SPORT"] = p[TCP].sport
        TOpt = p[TCP].options
        if ((TOpt[0])[0] == 'MSS'):  # the MSS value used in sockets opened on the loopback interface does not correctly reflect the one used in other interfaces and shall thus be rewritten
            (TOpt[0])[1] = TCPFieldsValues["TCP_MSS"]
        TCPFieldsValues["TCP_OPTIONS"] = TOpt  # every other TCP option on the other hand remains the same regardless of the specific interface used
        stateManager["captureSuccessful"] = True  # in case of success the function also updates this flag's value to "True"
    except Exception:
        stateManager["captureSuccessful"] = False


# this function launches a secondary script in a subprocess in order to create an authentic socket on the loopback interface after a certain delay
# the function then uses scapy's sniff method to intercept the first SYN packet and extract relevant information from it (SourcePortOnly is set to "True" if the only information needed is the Source Port Number)
def scoutSourcePort(interfaceInfo, stateManager, port):
    try:
        stateManager["captureSuccessful"] = False  # before attempting a capture, the global flag is set to "False". If the capture is successful, the callback function passed to scapy's sniff method will set it back to "True"
        filterMaskExtraData = "ip && tcp && src host " + interfaceInfo["LOOPBACK_ADDRESS"] + " && dst host " + interfaceInfo["LOOPBACK_ADDRESS"] + " && tcp[13]==2"  # filter passed to the sniff method: the only relevant packets are tcp/ip packet with source and destination address set to "127.0.0.1" and the SYN flag set to 1
        selfSocket = ['python' , 'SpawnSocket.py', interfaceInfo["LOOPBACK_ADDRESS"], str(port), str(0.05)]
        subprocess.Popen(selfSocket, shell=False)
        sniff(iface=interfaceInfo["LOOPBACK_INTERFACE_NAME"], filter=filterMaskExtraData, prn=lambda x : captureSourcePort(x), count=1, timeout=0.5)
    except Exception:
        stateManager["captureSuccessful"] = False
    return stateManager["captureSuccessful"]


# This function is invoked when a message received by mistake by the Covert Receiver has triggered unwanted behaviour and is used to identify the error's nature
# Accepts the message as input, returns an integer representing a specific error
def identifyError(message):
    termPosition = message // (2**28)
    message = message % (2**28)
    if message in [
        errorCorrection["FatalError"],
        errorCorrection["Delete4Char"],
        errorCorrection["DeleteSeparator"],
        errorCorrection["DeleteSeparatorAnd1"],
        errorCorrection["DeleteSeparatorAnd2"],
        errorCorrection["DeleteSeparatorAnd3"]
    ]:
        return error["MessageCompromised"]  # fatal error: the covert receiver has mistakenly received an error code and deleted part of the transmission when it was not supposed to
    separator = 21
    totalChar = 0
    while separator >= 0 :
        next = message // (2**separator)
        if (totalChar + 1) == termPosition and next == 4:
            TerminationError = "Termination" + str(totalChar)
            return error[TerminationError]  # termination error: the covert receiver has mistakenly received a certain number of invalid characters followed by the "termination" character
        message = message % (2**separator)
        separator = separator - 7
        totalChar = totalChar + 1
    return error["FourInvalidChars"]  # four characters error: the covert receiver has mistakenly received four invalid characters


# This function accepts as input a raw ISN, an IP Identification value and the Covert Receiver's address. It then proceeds to masquerade the sequence number to conceal the hidden message
def encryptISN(rawISN, IDValue, covert_receiver_address):
    IPbytes = covert_receiver_address.split(".")  # the receiver address is separated using "." to obtain its individual bytes
    random.seed(IDValue*(2**16) + int(IPbytes[2])*(2**8) + int(IPbytes[3]))  # the IP Identification value together with the last two bytes of the Receiver's address are used as a seed for python's PRNG function
    return rawISN ^ (int(random.random()*(2**32)))  # The output of PRNG is then combined with the raw ISN with a XOR operation


# This function is used to wait for a certain amount of time before proceeding with the next transmission
def wait_interval(wait_parameters, TS_interval_separator):
    waitVector = wait_parameters["list"]
    waitCounter = wait_parameters["counter"]
    NEXT_WAIT = waitVector[waitCounter]
    wait_parameters["counter"] = (waitCounter + 1) % (len(waitVector))
    NEXT_WAIT = NEXT_WAIT + random.random()*(1/100)
    elapsed = time.time() - TS_interval_separator
    if (NEXT_WAIT - elapsed > 0):  # time spent for the former packet transmission (if present) is effectively subtracted from the waiting time
        time.sleep(NEXT_WAIT - elapsed)


# ? disable promiscous mode in scapy
conf.sniff_promisc = 0
# ? load secret tranmission data
secret_message = ""
covert_receiver_address = ""
port = 443
if not os.path.exists(pathConf):
    print("No configuration file found. Exiting...")
    sys.exit()  # if no configuration file is found, terminate program
with open(pathConf, "r") as f:
    config = json.load(f)
    secret_message = config["secret_message"]  # read secret message from configuration files
    covert_receiver_address = config["covert_receiver_address"]  # read receiver address from configuration files
    port = int(config["port"])  # read destination port from configuration files
if len(secret_message) == 0:
    print("No secret message found. Exiting...")
    sys.exit()  # if no secret message is read, terminate program
else:
    print("message length: " + str(len(secret_message)))
    secret_message = secret_message + (chr(4))  # if a secret message is read, append the "termination character" to it (this character is EOT in ASCII)
# ? initialize interface info and choose interface used for transmission
refreshRoutes(interfaceInfo=interfaceInfo)  # fetch potential candidates among interfaces capable of reaching the outer internet
addInterfaceIndex(interfaceInfo=interfaceInfo)  # assign index to each candidate
chooseInterface(interfaceInfo=interfaceInfo, stateManager=stateManager)  # choose the first valid candidate that also has a currently active connection
fetchEtherSRC(interfaceInfo=interfaceInfo, stateManager=stateManager)  # fetch mac address of the chosen interface
fetchEtherDST(interfaceInfo=interfaceInfo, stateManager=stateManager)  # fetch mac address of the default gateway used by the chosen interface
scoutTCPSettings(TCPFieldsValues=TCPFieldsValues)  # discover the tcp settings on this host
print("Covert sender address: " + interfaceInfo["Covert_Sender_Address"])
print("Covert receiver address: " + covert_receiver_address)
print("Transmission Interface: " + interfaceInfo["Layer2_Interface"])
print("Transmission Interface MAC Address: " + interfaceInfo["Layer2_Source_Address"])
print("Transmission Gateway MAC Address: " + interfaceInfo["Layer2_Destination_Address"])
filterMask = "ip && tcp && dst host " + covert_receiver_address + " && (tcp[13] & 1!=0 )"  # filter option for the sniff method when listening for the outgoing FIN packet
filterMaskRst = "ip && tcp && src host " + covert_receiver_address + " && dst host " + interfaceInfo["Covert_Sender_Address"] + " && tcp[13]==20"  # filter used by scapy's sniff method upon listening for the Receiver's RST answer
TCPFieldsValues["TCP_SPORT"] = random.randrange(TCPFieldsValues["TCP_DYNAMIC_PORT_RANGE_NUMBER_OF_PORTS"]) + TCPFieldsValues["TCP_DYNAMIC_PORT_RANGE_START_PORT"] + 1  # assign a default value to Source Port (based on dynamic port range discovered in the step before). It will only be used if "Source Port Reservation" fails somehow
# ? split secret message into 4 byte chunks (rawISNs)
rawISNs = []  # Prepare list containing raw ISNs values to use in forged packets
while len(secret_message) != 0:  # parse the secret message string and create a list of raw sequence numbers containing its characters
    if len(secret_message) > 4:  # since sequence numbers are 32 bits long and an ASCII character is 7 bits long, a total of four ASCII character can fit in a single raw ISN
        characterOne = ord(secret_message[0])
        characterTwo = ord(secret_message[1])
        characterThree = ord(secret_message[2])
        characterFour = ord(secret_message[3])
        secret_message = secret_message[4:]  # after the four characters are stored in a raw ISN, they are also eliminated from the string
        ISN = (characterOne * (2**21)) + (characterTwo * (2**14)) + (characterThree * (2**7)) + (characterFour)
        rawISNs.append(ISN)  # the four characters are stored in the 28 less significant bits of the raw ISN. The four starting bits are always random.
    else:  # if four or less characters are left in the secret message string, they are instead copied one at the time. Any free space remaining on the right is padded with 0
        ISN = 0
        counter = 4
        while len(secret_message) != 0:
            nextChar = ord(secret_message[0])
            secret_message = secret_message[1:]
            ISN = ISN * (2**7) + nextChar
            counter = counter - 1
        termPosition = 4 - counter  # the ISN that contains the EOT character must also include a label in its 4 most significant bits to allow the receiver to recognize it
        termPosition = termPosition*(2**28)
        ISN = ISN * (2**(7*counter)) + termPosition
        rawISNs.append(ISN)
# ? create forged packet and initialize fields that won't change during transmission
ForgedPacket = Ether()/IP()/TCP()  # create the packet
ForgedPacket[Ether].src = interfaceInfo["Layer2_Source_Address"]
ForgedPacket[Ether].dst = interfaceInfo["Layer2_Destination_Address"]
ForgedPacket[Ether].type = interfaceInfo["Layer2_Type"]
ForgedPacket[IP].dst = covert_receiver_address  # assign destination address
ForgedPacket[IP].src = interfaceInfo["Covert_Sender_Address"]  # assign sender address
ForgedPacket[TCP].dport = port  # assign destination port
ForgedPacket[TCP].flags = 2  # SYN flag is set to 1
lastISN = -1
nextISN = lastISN  # buffer variable used to store the processed sequence number that will be assigned to the forged packet
IDValue = TCPFieldsValues["IP_ID"]
TS_interval_separator = 0  # variable used to separate the time intervals between each transmission
FirstPacket = True  # variable used to signal whether the packet being transmitted is the very first one
initialTime = time.time()
# ? iterate over secret message chunks and send them one by one
while (
    len(rawISNs) != 0  # while there are still raw ISNs to transmit
    and stateManager["reachedHost"]  # and the receiver is still reachable
    and not stateManager["abortOperations"]  # and transmission was not compromised
):
    print(str(len(rawISNs)) + " more isn to go")
    nextRawISN = rawISNs.pop(0)  # get next ISN to transmit
    nextISN = lastISN
    while nextISN == lastISN:
        IDValue = (IDValue + 1) % (2**16)
        nextISN = encryptISN(rawISN=nextRawISN, IDValue=IDValue, covert_receiver_address=covert_receiver_address)  # obtain a processed sequence number value
    lastISN = nextISN
    ForgedPacket[TCP].seq = nextISN  # assign new processed sequence number and new id value
    ForgedPacket[IP].id = IDValue
    scoutedPort = scoutSourcePort(interfaceInfo=interfaceInfo, stateManager=stateManager, port=port)  # scout the source port
    if not scoutedPort:  # reserve a new source port
        TCPFieldsValues["TCP_SPORT"] = (TCPFieldsValues["TCP_SPORT"] + 1) % (2**16)
        if TCPFieldsValues["TCP_SPORT"] == 0:
            TCPFieldsValues["TCP_SPORT"] = TCPFieldsValues["TCP_DYNAMIC_PORT_RANGE_START_PORT"] + 1
    # ? initialize the remaining packet fields depending on the values obtained during source port scouting
    ForgedPacket[TCP].sport = TCPFieldsValues["TCP_SPORT"]
    ForgedPacket[IP].tos = TCPFieldsValues["IP_TOS"]  # IP Terms of service
    ForgedPacket[IP].flags = TCPFieldsValues["IP_FLAGS"]  # IP Flags
    ForgedPacket[IP].ttl = TCPFieldsValues["IP_TTL"]  # IP Time to leave
    ForgedPacket[IP].options = TCPFieldsValues["IP_OPTIONS"]  # IP Options
    ForgedPacket[TCP].window = TCPFieldsValues["TCP_WINDOW"]  # TCP Window size
    ForgedPacket[TCP].options = TCPFieldsValues["TCP_OPTIONS"]  # TCP Options
    del ForgedPacket[IP].chksum
    del ForgedPacket[TCP].chksum
    ForgedPacket = ForgedPacket.__class__(bytes(ForgedPacket))  # The computation of fields such as IP Initial Header Length, TCP Data offset and Checksums is delegated to scapy
    # ? reset state variables before transmission
    stateManager["correctlyDelivered"] = False  # reset variable that keeps track of whether the packet was correctly delivered
    stateManager["currentError"] = error["NoError"]  # reset variable that keeps track of possible errors
    stateManager["reachedHost"] = False  # reset variable that keeps track of whether the receiver has sent any RST answer at all
    if not FirstPacket:  # if this is not the first packet, before transmitting we must always ensure a certain amount of time has passed to avoid beaconing
        wait_interval(wait_parameters=wait_parameters, TS_interval_separator=TS_interval_separator)
    FirstPacket = False
    TS_interval_separator = time.time()  # reset the interval separator right before each transmission
    # ? transmission of the main forged packet
    sendp(ForgedPacket, iface=interfaceInfo["Layer2_Interface"], verbose=False)
    if listenForRST(  # listen for a reply using scapy's sniff method
        filterMaskRst=filterMaskRst,
        delay=2,
        interfaceInfo=interfaceInfo,
        stateManager=stateManager,
        originalPacket=ForgedPacket,
        Ntransmissions=0
    ):
        stateManager["reachedHost"] = True  # if the receiver answers, this variable signals it was possible to reach it
        stateManager["correctlyDelivered"] = True  # if the message is correctly delivered, the receiver will automatically ignore any future packet that hasn't changed its sequence number (thus eliminating the risk of errors)
    # ? preparation of the single retransmission packet (this variant always uses one single retransmission, at least one retransmission is always required to improve robustness)
    IDValue = (IDValue + 1) % (2**16)
    ForgedPacket[IP].id = IDValue  # the packet is assigned a new IDValue
    del ForgedPacket[IP].chksum  # the checksum is deleted and then recomputed
    ForgedPacket = ForgedPacket.__class__(bytes(ForgedPacket))
    wait_interval(wait_parameters=wait_parameters, TS_interval_separator=TS_interval_separator)  # wait for a certain amount of time before retransmitting to avoid beaconing
    TS_interval_separator = time.time()
    # ? delivery of the retransmission packet
    sendp(ForgedPacket, iface=interfaceInfo["Layer2_Interface"], verbose=False)  # the retransmission packet is sent
    if listenForRST(  # listen for a reply using scapy's sniff method
        filterMaskRst=filterMaskRst,
        delay=2,
        interfaceInfo=interfaceInfo,
        stateManager=stateManager,
        originalPacket=ForgedPacket,
        Ntransmissions=1
    ):
        stateManager["reachedHost"] = True
        if not stateManager["correctlyDelivered"]:
            # ? "correctlyDelivered" is only set to True if the original packet had arrived correctly. If False, it implies the receiver has accepted wrong information
            message = encryptISN(ForgedPacket[TCP].seq, ForgedPacket[IP].id, ForgedPacket[IP].dst)  # determine message content incorrectly accepted by the receiver
            stateManager["currentError"] = identifyError(message)
    # ? if the receiver was unreachable or we just finished signaling a "fatal error", transmission must end at this point
    if not stateManager["reachedHost"] or nextRawISN == errorCorrection["FatalError"]:
        stateManager["abortOperations"] = True
    # ? if the receiver has accepted wrong information, we must first send an error correction code and then try again with the same packet
    if not stateManager["correctlyDelivered"]:
        rawISNs.insert(0, nextRawISN)  # reinsert last raw ISN so a new attempt at transmitting it is later made
        if stateManager["currentError"] == error["Termination0"]:  # also schedule for transmission an appropriate error correction code
            rawISNs.insert(0, errorCorrection["DeleteSeparator"])
        elif stateManager["currentError"] == error["Termination1"]:
            rawISNs.insert(0, errorCorrection["DeleteSeparatorAnd1"])
        elif stateManager["currentError"] == error["Termination2"]:
            rawISNs.insert(0, errorCorrection["DeleteSeparatorAnd2"])
        elif stateManager["currentError"] == error["Termination3"]:
            rawISNs.insert(0, errorCorrection["DeleteSeparatorAnd3"])
        elif stateManager["currentError"] == error["FourInvalidChars"]:
            rawISNs.insert(0, errorCorrection["Delete4Char"])
        elif stateManager["currentError"] == error["MessageCompromised"]:
            rawISNs.insert(0, errorCorrection["FatalError"])
        if stateManager["formerTransmissionError"] == error["NoError"]:  # the first error that occurs can be tolerated, but we must keep track of it: next time we won't be able to recover
            stateManager["formerTransmissionError"] = stateManager["currentError"]
        else:  # two errors in a row are not acceptable because sending multiple corrections might cause the receiver to cancel part of the message
            stateManager["abortOperations"] = True
    else:  # if the message arrived correctly, we reset the error tracker
        stateManager["formerTransmissionError"] = error["NoError"]
    # ? report current transmission status
    print("|| Correctly delivered: "+str(stateManager["correctlyDelivered"])+" || Error code: " + str(stateManager["formerTransmissionError"]) + " || Reached host: " + str(stateManager["reachedHost"]) + " || Abort: " + str(stateManager["abortOperations"]) + " || ")

finishTime = time.time() - initialTime
print("Finished! Total transmission time: " + str(finishTime) + " seconds, or: " + str(math.floor(finishTime / 60)) + " minutes and " + str(finishTime % 60) + " seconds.")
