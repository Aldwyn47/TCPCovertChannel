# TCPCovertChannel

Implementation of the idea behind the paper "A TCP-based Covert Channel with Integrity Check and Retransmission", submitted to the Journal of Information Security edited by Springer.

The paper presents the description of a covert channel using the TCP header as the means to hide and transport information from a Sender to a Receiver on two different networks. We apply network steganography by embedding the message into the Sequence Number field of TCP (four characters of text are sent for each TCP segment). The novelty of the paper resides in the robustness of the channel and the integrity enforced on data: some errors codes are transmitted as well and used to retransmit the message in case of loss (we use SYN segments to establish a new connection to send a piece of message, so we do not inherit the robustness of TCP ourselves), and we "sign" the message by applying a random function on the id field of the TCP header and xoring it with the message. The purpose is to better hide the message (for example, vowels would have a higher frequency of appearance), and have also a way to check if the message has been altered during the transmission.


We provide an implementation of the channel in Windows OS, by mocking the behaviour of its TCP/IP stack and using Windows commands to retrieve information on the Sender machine. Indeed, the channel could be implemented with different stacks as well.


Then, we test the channel in different network environments: the Receiver always successfully receives the correct message. Moreover, we also check if the channel is stealthy by using two Intrusion Detection Systems (Suricata and Zeek).


Finally, as far as we know, we perform statistical analysis to detect a covert channel: we adopt RITA (Real Intelligence Threat Analytics) with the purpose to understand how much our proposal can be detected as a "beaconing" tool, thus following the behaviour of some malware. We study the code of RITA and we lower the alarm score obtained by our channel below the one of false positives.

How to cite: <br />
@inproceedings{DBLP:conf/pst/BistarelliIS23, <br />
  author       = {Stefano Bistarelli and <br />
                  Andrea Imparato and <br />
                  Francesco Santini}, <br />
  title        = {A TCP-based Covert Channel with Integrity Check and Retransmission}, <br />
  booktitle    = {{PST}}, <br />
  pages        = {1--7}, <br />
  publisher    = {{IEEE}}, <br />
  year         = {2023} <br />
} <br />
