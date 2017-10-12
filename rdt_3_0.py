import Network
import argparse
from time import sleep
import hashlib
import time

def isACK(input_string, seq_num) :
    if (input_string == str("ACK" + str(seq_num))):
        return True

    else:
        return False


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ack_num = 1
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        pass

    def rdt_1_0_receive(self):
        pass
    
    def rdt_2_1_send(self, msg_S):
        pass
        
    def rdt_2_1_receive(self):
        pass
    
    def rdt_3_0_send(self, message):
    
#        sand_packet = Packet(self.seq_num, message)
#        self.seq_num += 1       
#        self.network.udt_send(sand_packet.get_byte_S())

        timeout = 2

        # alternating sequence numbers
        if self.seq_num == 0:
            self.seq_num = 1
        else:
            self.seq_num = 0

        # creation of sand_packet
        sand_packet = Packet(self.seq_num, message)
        self.network.udt_send(sand_packet.get_byte_S())

        # timer start
        start_time = time.time()

        # continue receiving packets until it is not corrupt and proper ACK
        received_packet = self.network.udt_receive()
        while ( Packet.corrupt(received_packet) or isACK(received_packet, self.ack_num)):
            elapsed_time = time.time() - start_time

            received_packet = self.network.udt_receive()

            # timeout
            if elapsed_time >= timeout:
                self.network.udt_send(sand_packet.get_byte_S())
                start_time = time.time()

        # upon exiting the loop, received packet is not corrupt and the isACK is proper
        # ( ~ (p or q) = ~p and ~q)

        # since it's a proper packet, the ACK can alternate
        if self.ack_num == 0:
            self.ack_num = 1
        else:
            self.ack_num = 0

        
    def rdt_3_0_receive(self):
        
#        ret_S = None
#        byte_S = self.network.udt_receive()
#        self.byte_buffer += byte_S
#        #keep extracting packets - if reordered, could get more than one
#        while True:
#            #check if we have received enough bytes
#            if(len(self.byte_buffer) < Packet.length_S_length):
#                return ret_S #not enough bytes to read packet length
#            #extract length of packet
#            length = int(self.byte_buffer[:Packet.length_S_length])
#            if len(self.byte_buffer) < length:
#                return ret_S #not enough bytes to read the whole packet
#            #create packet from buffer content and add to return string
#            p = Packet.from_byte_S(self.byte_buffer[0:length])
#            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
#            #remove the packet bytes from the buffer
#            self.byte_buffer = self.byte_buffer[length:]
#            #if this was the last packet, will return on the next iteration

        output_string = None
        received_bytes = self.network.udt_receive()
        # received_bytes is a packet
        self.byte_buffer += received_bytes

        while True:
            if(len(self.byte_buffer) < Packet.length_S_length):
                return output_string

            length = int(self.byte_buffer[:Packet.length_S_length])

            if len(self.byte_buffer) < length:
                return output_string

            p = Packet.from_byte_S(self.byte_buffer[0:length])

            if (output_string == None):
                output_string = p.msg_S
            else:
                output_string += p.msg_S

            self.byte_buffer = self.byte_buffer[length:]

        return output_string


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        print 'MSG_FROM_CLIENT'
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        
        

