import os
import random
import time

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

# ! NETWORK CONFIGURATION FOR THE COVERT RECEIVER, MUST BE CONFIGURED MANUALLY BEFORE USE
receiver_network_configuration = {
    "Public_Receiver_Address" : "",  # MANUALLY INSERT HERE the public address of the covert receiver, the one used as destination by the covert sender
    "Local_Receiver_Address" : "",  # MANUALLY INSERT HERE the address used by the covert receiver in case it is a private host on a local network (will be used to filter packets on the local network not directed to the covert receiver in case of background noise)
    "Layer2_Interface" : "",  # MANUALLY INSERT HERE the name of the layer 2 interface used by the receiver on its local network (can be discovered with scapy's conf.ifaces.show() command)
    "Layer2_Source_Address" : "",  # MANUALLY INSERT HERE the mac address that identifies the receiver's interface on its local network. Can be discovered using Windows' "ipconfig" command
    "Layer2_Destination_Address" : "",  # MANUALLY INSERT HERE the mac address that identifies the gateway on the receiver's local network. Can be discovered using Windows' "arp -a" command
    "Layer2_Type" : 2048,  # LEAVE THIS TO 2048 value of the "type" field in layer 2. Leave this to "2048" as it identifies the frame as "ipv4"
    "port" : 443,  # port on which the receiver listens for secret information, must match the "port" parameter used by the sender. Leave it on "443" unless the Sender's port was also changed.
}

# DIRECTORY WHERE RECEIVED INFORMATION IS STORED
pathReceivedData = os.path.join(os.getcwd(), 'ReceivedTransmissions')

# ISN CACHE
ISNs_cache = {}  # Buffer variable that stores records associated to different sending IP Addresses. Each record contains the sequence number and arrival time of the last packet received from a given IP
cache_configuration = {
    "maxWait" : 5400,  # how long each record is allowed to stay in the buffer, value must be high enough to match the sender's waiting times
    "clearInterval" : 5400,  # how often the buffer should be analyzed to clear expired records
    "maxNumberHosts" : 100000,  # how many records the buffer can hold at most
    "lastClearRound" : time.time()  # Variable that keeps track of the last time the buffer was cleared
}

# DICTIONARY THAT CONTAINS ERROR CORRECTION CODES SENT BY THE SENDER
errorCorrectionCodes = {
    "DeleteSeparator" : 4026531840,       # 1111 0000000 0000000 0000000 0000000 delete last transmission separator
    "DeleteSeparatorAnd1" : 4026531841,   # 1111 0000000 0000000 0000000 0000001 delete last transmission separator and 1 character
    "DeleteSeparatorAnd2" : 4026531842,   # 1111 0000000 0000000 0000000 0000010 delete last transmission separator and 2 characters
    "DeleteSeparatorAnd3" : 4026531843,   # 1111 0000000 0000000 0000000 0000011 delete last transmission separator and 3 characters
    "Delete4Char" : 4026531844,           # 1111 0000000 0000000 0000000 0000100 delete last four characters
    "FatalError" : 4026531845             # 1111 0000000 0000000 0000000 0000101 fatal error
}

# TRANSMISSION SEPARATOR
TRANSMISSION_SEPARATOR = "\n-EOT-" + chr(0) + "\n"  # Transmission separator string: it is appended in every txt file after the end of each transmission (signaled by the sender using the ASCII EOT character)


# function used to decrypt sequence number and restore raw ISNs, allowing the receiver to read the message
def decrypt(ISN, IDValue, receiver_network_configuration):
    IPbytes = (receiver_network_configuration["Public_Receiver_Address"]).split(".")
    random.seed(IDValue*(2**16) + int(IPbytes[2])*(2**8) + int(IPbytes[3]))
    return ISN ^ (int(random.random()*(2**32)))


# function used to delete a given number of characters in case of error
def deleteChars(offset, file_path):
    testo = ""
    with open(file_path, "r") as file:
        testo = file.read()
    testo = testo[:-offset]
    with open(file_path, "w") as file:
        file.write(testo)


# function used to process a packet's content if it does effectively contain a valid message
def acceptContent(message, IP):
    file_path = os.path.join(pathReceivedData, IP + ".txt")
    print("ACCEPTED CONTENT:")
    try:
        if message == errorCorrectionCodes["DeleteSeparator"]:  # delete last separator
            deleteChars(offset=len(TRANSMISSION_SEPARATOR), file_path=file_path)
            print("delete last separator")
            return
        elif message == errorCorrectionCodes["DeleteSeparatorAnd1"]:  # delete last separator and 1 character
            deleteChars(offset=len(TRANSMISSION_SEPARATOR) + 1, file_path=file_path)
            print("delete last separator and 1 character")
            return
        elif message == errorCorrectionCodes["DeleteSeparatorAnd2"]:  # delete last separator and 2 characters
            deleteChars(offset=len(TRANSMISSION_SEPARATOR) + 2, file_path=file_path)
            print("delete last separator and 2 characters")
            return
        elif message == errorCorrectionCodes["DeleteSeparatorAnd3"]:  # delete last separator and 3 characters
            deleteChars(offset=len(TRANSMISSION_SEPARATOR) + 3, file_path=file_path)
            print("delete last separator and 3 characters")
            return
        elif message == errorCorrectionCodes["Delete4Char"]:  # delete last 4 characters
            deleteChars(offset=4, file_path=file_path)
            print("delete last 4 characters")
            return
        elif message == errorCorrectionCodes["FatalError"]:  # fatal error
            with open(file_path, "a", encoding='utf-8') as file:
                file.write("***FATAL ERROR***" + TRANSMISSION_SEPARATOR)
            print("fatal error")
            return
    except Exception:
        pass
    termPosition = message // (2**28)  # if the first four bits have a value in the 1-4 range they are a label that identifies which of the four characters is actually the termination character
    message = message % (2**28)  # discard the four most significan bits
    with open(file_path, "a", encoding='utf-8') as file:
        separator = 21  # separator used to parse 7 bits at a time
        charPosition = 1  # counter to keep track of which one of the four characters is being parsed next
        while separator >= 0:
            nextChar = message // (2**separator)
            if charPosition == termPosition and nextChar == 4:  # if the EOT character is encountered, append transmission separator and close file (finished transmission)
                file.write(TRANSMISSION_SEPARATOR)
                print("EOT")
                return
            else:
                print(chr(nextChar))
                file.write(chr(nextChar))
            message = message % (2**separator)
            separator = separator - 7
            charPosition = charPosition + 1


# Function used to clear old records from the record buffer
# Accepts as input current time
def clearOldRecords(currentTime, ISNs_cache, cache_configuration):
    removeKeys = []
    for ip in ISNs_cache :  # check all keys in the dictionary
        if ((ISNs_cache[ip])["time_of_arrival"] + cache_configuration["maxWait"]) < currentTime :  # if a record has expired, copy its key in the list of keys to remove
            removeKeys.append(ip)
    for ip in removeKeys :  # remove all keys marked for deletion
        ISNs_cache.pop(ip)
    cache_configuration["lastClearRound"] = currentTime  # update global variable to keep track of the last time the buffer was cleared
    print("Old records cleared.")


# Function used to create the receiver's RST answer to an incoming packet
def sendRST(incoming_packet, receiver_network_configuration):
    t1 = time.time()
    AnswerPKT = Ether()/IP()/TCP()  # Packet used in RST answers
    AnswerPKT[Ether].src = receiver_network_configuration["Layer2_Source_Address"]
    AnswerPKT[Ether].dst = receiver_network_configuration["Layer2_Destination_Address"]
    AnswerPKT[Ether].type = receiver_network_configuration["Layer2_Type"]
    AnswerPKT[IP].flags = 2
    AnswerPKT[IP].dst = incoming_packet[IP].src
    AnswerPKT[IP].src = incoming_packet[IP].dst
    AnswerPKT[TCP].flags = 20
    AnswerPKT[TCP].window = 0
    AnswerPKT[TCP].sport = incoming_packet[TCP].dport
    AnswerPKT[TCP].dport = incoming_packet[TCP].sport
    AnswerPKT[TCP].ack = (incoming_packet[TCP].seq + 1) % (2**32)
    random.seed(incoming_packet[IP].seq + incoming_packet[IP].id)
    AnswerPKT[IP].id = int(random.random()*(2**16))  # the id field contains an encrypted signature based on the original packet's IP Identification and TCP sequence number
    AnswerPKT = AnswerPKT.__class__(bytes(AnswerPKT))
    print("answer assembled in: " + str(time.time()-t1))
    sendp(AnswerPKT, iface=receiver_network_configuration["Layer2_Interface"])
    print("answer sent in: " + str(time.time()-t1))


# Function used to inspect each incoming packet that passes scapy's sniff filter
def checkPacket(incoming_packet, receiver_network_configuration, ISNs_cache, cache_configuration):
    print("Received packet from " + incoming_packet[IP].src)
    # ? always send a RST packet as an answer to the incoming packet
    sendRST(incoming_packet=incoming_packet, receiver_network_configuration=receiver_network_configuration)
    currentTime = time.time()  # take note of the arrival time
    hostList = ISNs_cache.get(incoming_packet[IP].src)  # check ISN cache to see if a record associated with the packet sender's IP address exists
    # ? only accept the packet's content if a cache record for the sender's IP doesn't exist or if the sequence number stored in it differs, otherwise it's a retransmission
    if hostList is None or hostList["ISN_value"] != incoming_packet[TCP].seq:
        # store in cache the packet's sequence number and its time of arrival
        ISNs_cache[incoming_packet[IP].src] = {
            "time_of_arrival": currentTime,
            "ISN_value": incoming_packet[TCP].seq
        }
        message = decrypt(ISN=incoming_packet[TCP].seq, IDValue=incoming_packet[IP].id, receiver_network_configuration=receiver_network_configuration)  # decrypt packet's ISN to obtain original raw ISN
        acceptContent(message=message, IP=incoming_packet[IP].src)  # process the incoming information
        # ? remove expired records from the ISN cache if too much time has passed since the last clear or if it contains too many records
        if (
            currentTime > (cache_configuration["lastClearRound"] + cache_configuration["clearInterval"])
            or len(ISNs_cache) >= cache_configuration["maxNumberHosts"]
        ):
            clearOldRecords(currentTime=currentTime, ISNs_cache=ISNs_cache, cache_configuration=cache_configuration)


conf.sniff_promisc = 0  # disable promiscous mode in scapy
if not os.path.exists(pathReceivedData):  # create the directory where received transmissions are stored if it doesn't exist
    os.makedirs(pathReceivedData)
filterMask = "ip && tcp && dst host " + receiver_network_configuration["Local_Receiver_Address"] + " && dst port " + str(receiver_network_configuration["port"]) + " && tcp[13]==2"  # filter option for scapy's sniff method: we only listen to TCP packets directed to the receiver's address on a certain destination port with SYN flag set to 1
th = AsyncSniffer(iface=receiver_network_configuration["Layer2_Interface"], filter=filterMask, prn=lambda x : checkPacket(incoming_packet=x, receiver_network_configuration=receiver_network_configuration, ISNs_cache=ISNs_cache, cache_configuration=cache_configuration), count=0)  # start listening
th.start()
th.join()
