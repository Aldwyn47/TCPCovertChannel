from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.all import *

#************************MANUALLY INITIALIZE THE FOLLOWING PARAMETERS************************
Public_Receiver_Address = "" #MANUALLY INSERT HERE the public address of the covert receiver, the one used as destination by the covert sender
Local_Receiver_Address = "" #MANUALLY INSERT HERE the address used by the covert receiver in case it is a private host on a local network (will be used to filter packets on the local network not directed to the covert receiver in case of background noise)
Layer2_Interface = "" # MANUALLY INSERT HERE the name of the layer 2 interface used by the receiver on its local network (can be discovered with scapy's conf.ifaces.show() command)
Layer2_Source_Address = "" #MANUALLY INSERT HERE the mac address that identifies the receiver's interface on its local network. Can be discovered using Windows' "ipconfig" command
Layer2_Destination_Address = "" #MANUALLY INSERT HERE the mac address that identifies the gateway on the receiver's local network. Can be discovered using Windows' "arp -a" command
PATHReceivedData = r'C:\Users\Username\Desktop\ReceivedTransmissions\ ' #MANUALLY INSERT HERE the path of the folder where received information must be stored. Must terminate with a blank space after \ as strings in python cannot terminate with \ . The blank space is automatically trimmed in the next line of code.
PATHReceivedData = PATHReceivedData[:-1]
Layer2_Type = 2048 #value of the "type" field in layer 2. Leave this to "2048" as it identifies the frame as "ipv4"
PORT = 443 #port on which the receiver listens for secret information, must match the PORT parameter used by the sender. Leave it on "443" unless the Sender's port was also changed.

#ISN RECORD BUFFER CONFIGURATION
lastTransmissionRecord = {} #Buffer variable that stores records associated to different sending IP Addresses. Each record contains the sequence number and arrival time of the last packet received from a given IP
maxWait = 5400 #how long each record is allowed to stay in the buffer
clearInterval = 5400 #how often the buffer should be analyzed to clear expired records
maxNumberHosts = 100000 #how many records the buffer can hold at most
lastClearRound = time.time() #Variable that keeps track of the last time the buffer was cleared

#DICTIONARY THAT CONTAINS THE ERROR CORRECTION CODES
ErrorCorrection = { 
    "DeleteSeparator" : 4026531840,       #1111 0000000 0000000 0000000 0000000 delete last transmission separator
    "DeleteSeparatorAnd1" : 4026531841,   #1111 0000000 0000000 0000000 0000001 delete last transmission separator and 1 character
    "DeleteSeparatorAnd2" : 4026531842,   #1111 0000000 0000000 0000000 0000010 delete last transmission separator and 2 characters
    "DeleteSeparatorAnd3" : 4026531843,   #1111 0000000 0000000 0000000 0000011 delete last transmission separator and 3 characters
    "Delete4Char" : 4026531844,           #1111 0000000 0000000 0000000 0000100 delete last four characters
    "FatalError" : 4026531845             #1111 0000000 0000000 0000000 0000101 fatal error
}

#TRANSMISSION SEPARATOR
TRANSMISSION_SEPARATOR = "\n-EOT-" + chr(0) + "\n" #Transmission separator string: it is appended in every txt file after the end of each transmission (signaled by the sender using the ASCII EOT character)



#function used to decrypt sequence number and restore raw ISNs, allowing the receiver to read the message
def decrypt(ISN, IDValue):
    IPbytes = Public_Receiver_Address.split(".")
    random.seed(IDValue*(2**16) + int(IPbytes[2])*(2**8) + int(IPbytes[3]))
    return ISN^(int(random.random()*(2**32)))

#function used to delete a given number of characters in case of error
def deleteChars(IP, offset):
    file = open(PATHReceivedData + IP + ".txt", "r")
    testo = file.read()
    file.close()
    testo = testo[:-offset]
    file = open(PATHReceivedData + IP + ".txt", "w")
    file.write(testo)
    file.close()

#function used to process a packet's content if it does effectively contain a valid message
def acceptContent(message, IP, FirstReceived=False):
    print("ACCEPTED CONTENT:")
    try:
        if not FirstReceived and message == ErrorCorrection["DeleteSeparator"]: #delete last separator
            deleteChars(IP, len(TRANSMISSION_SEPARATOR))
            print("delete last separator")
            return
        elif not FirstReceived and message == ErrorCorrection["DeleteSeparatorAnd1"]: #delete last separator and 1 character
            deleteChars(IP, len(TRANSMISSION_SEPARATOR)+1)
            print("delete last separator and 1 character")
            return
        elif not FirstReceived and message == ErrorCorrection["DeleteSeparatorAnd2"]: #delete last separator and 2 characters
            deleteChars(IP, len(TRANSMISSION_SEPARATOR)+2)
            print("delete last separator and 2 characters")
            return
        elif not FirstReceived and message == ErrorCorrection["DeleteSeparatorAnd3"]: #delete last separator and 3 characters
            deleteChars(IP, len(TRANSMISSION_SEPARATOR)+3)
            print("delete last separator and 3 characters")
            return
        elif not FirstReceived and message == ErrorCorrection["Delete4Char"]: #delete last 4 characters
            deleteChars(IP, 4)
            print("delete last 4 characters")
            return
        elif not FirstReceived and message == ErrorCorrection["FatalError"]: #fatal error
            file = open(PATHReceivedData + IP + ".txt", "a", encoding='utf-8')
            file.write("***FATAL ERROR***"+TRANSMISSION_SEPARATOR)
            file.close()
            print("fatal error")
            return
    except:
        ()
    termPosition = message // (2**28) #if the first four bits have a value in the 1-4 range they are a label that identifies which of the four characters is actually the termination character
    message = message % (2**28) #discard the four most significan bits
    file = open(PATHReceivedData + IP + ".txt", "a", encoding='utf-8') #open txt file associated with the sender's IP address in "append" mode
    separator = 21 #separator used to parse 7 bits at a time
    charPosition = 1 #counter to keep track of which one of the four characters is being parsed next
    while separator>=0 :
        next = message // (2**separator)
        if charPosition == termPosition and next == 4: #if the EOT character is encountered, append transmission separator and close file (finished transmission)
            file.write(TRANSMISSION_SEPARATOR)
            file.close()
            print("EOT")
            return
        else:
            print(chr(next))
            file.write(chr(next)) 
        message = message % (2**separator)
        separator = separator - 7
        charPosition = charPosition + 1
    file.close()

#Function used to clear old records from the record buffer
#Accepts as input current time
def clearOldRecords(currentTime):
    global lastTransmissionRecord
    global lastClearRound
    removeKeys = []
    for ip in lastTransmissionRecord : #check all keys in the dictionary
        if ((lastTransmissionRecord[ip])[0] + maxWait) < currentTime : #if a record has expired, copy its key in the list of keys to remove
            removeKeys.append(ip)
    for ip in removeKeys : #remove all keys marked for deletion
        lastTransmissionRecord.pop(ip)
    lastClearRound = currentTime #update global variable to keep track of the last time the buffer was cleared
    print("Old records cleared.")

#Function used to create the receiver's RST answer to an incoming packet
def sendRST(p):
    t1 = time.time()
    AnswerPKT = Ether()/IP()/TCP() #Packet used in RST answers
    AnswerPKT[Ether].src = Layer2_Source_Address
    AnswerPKT[Ether].dst = Layer2_Destination_Address
    AnswerPKT[Ether].type = Layer2_Type
    AnswerPKT[IP].flags = 2
    AnswerPKT[IP].dst = p[IP].src
    AnswerPKT[IP].src = p[IP].dst
    AnswerPKT[TCP].flags = 20
    AnswerPKT[TCP].window = 0
    AnswerPKT[TCP].sport = p[TCP].dport
    AnswerPKT[TCP].dport = p[TCP].sport
    AnswerPKT[TCP].ack = (p[TCP].seq + 1)%(2**32)
    random.seed(p[IP].seq + p[IP].id)
    AnswerPKT[IP].id = int(random.random()*(2**16)) #the id field contains an encrypted signature based on the original packet's IP Identification and TCP sequence number
    AnswerPKT = AnswerPKT.__class__(bytes(AnswerPKT))
    print("answer assembled in: " + str(time.time()-t1))
    sendp(AnswerPKT, iface=Layer2_Interface)
    print("answer sent in: " + str(time.time()-t1))

#Function used to inspect each incoming packet that passes scapy's sniff filter
def checkPacket(p):
    global lastTransmissionRecord
    global lastClearRound
    sendRST(p)
    print("Received packet from " + p[IP].src)
    currentTime = time.time() #take note of the arrival time
    hostList = lastTransmissionRecord.get(p[IP].src) #extract from the record buffer the specific record associated to the sending IP address
    if hostList!=None and hostList[1]!=p[TCP].seq : #if a record for the sender's IP exists and the sequence number stored in it differs from the incoming packet's, process the packet's content (otherwise ignore it because it is a retransmission of a former packet)
        message = decrypt(p[TCP].seq, p[IP].id) #decrypt packet's sequence number to obtain original raw ISN
        hostList[1] = p[TCP].seq #save the original ISN (not raw ISN) in the record buffer
        hostList[0] = currentTime #also save the arrival time in the record buffer
        if currentTime > (lastClearRound + clearInterval) : #check if it is time to clear the record buffer, and do so if needed
            clearOldRecords(currentTime)
        lastTransmissionRecord[p[IP].src] = hostList #insert record in record buffer
        acceptContent(message, p[IP].src) #process the incoming message
    elif hostList == None : #if no record exists in the record buffer for the sender's IP, examine the incoming packet
        message = decrypt(p[TCP].seq, p[IP].id)
        if currentTime > (lastClearRound + clearInterval) or len(lastTransmissionRecord)>=maxNumberHosts : #clear the record buffer if full or if too much time has passed since last clear
            clearOldRecords(currentTime)
        if len(lastTransmissionRecord)<maxNumberHosts: #only create a new record in the record buffer if space is available
            lastTransmissionRecord[p[IP].src] = [currentTime, p[TCP].seq]
        else: #else signal an overload
            print("Record overflow!")
        acceptContent(message, p[IP].src, FirstReceived=True) #process the incoming message

conf.sniff_promisc = 0 #disable promiscous mode in scapy
filterMask = "ip && tcp && dst host "+Local_Receiver_Address+" && dst port "+str(PORT)+ " && tcp[13]==2" #filter option for scapy's sniff method: we only listen to TCP packets directed to the receiver's address on a certain destination port with SYN flag set to 1
th = AsyncSniffer(iface = Layer2_Interface, filter=filterMask, prn = lambda x : checkPacket(x), count = 0) #start listening
th.start()
th.join()