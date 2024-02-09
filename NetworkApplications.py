import argparse
import socket
import struct
import time
import random

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications')
        parser.set_defaults(func=ICMPPing, hostname='google.co.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    uniqueID = 0
    sendTime = 0
    receivedTime = 0
    ipHeader = None
    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply

        # split reply up into bytes and address. as stated on python library, the echo reply return value is made up of a pair containing these
        replyBytes, address = icmpSocket.recvfrom(1024) #assign enough bytes that we assume is enough for the reply
        
        # use python split function to extract header from bytes
        # the first 20 contain the data of ip header, the next 8 bytes are the ICMP header
        icmpHeader = replyBytes[20:28]
        self.ipHeader = replyBytes[15:20]
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        receivedTime = time.time()
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay = receivedTime - ICMPPing.sendTime
        # 4. Unpack the packet header for useful information, including the ID
        packetType, packetCode, packetChecksum, packetID, packetSequence = struct.unpack_from("BBHHH", icmpHeader, 0)
        # 5. Check that the ID matches between the request and reply
        if ID == packetID:
            # 6. Return total network delay
            print(delay)
            return delay
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ## Header is type (8) code (8) checksum (16) id (16) sequence(16)
        headerData = struct.pack("BBHHH",8,0,0, ID,1)
        #BBHHH is used because B is unsigned char of 1 byte and H is unsigned short of 2 bytes
        # so it is a format string for when the packet is unpacked it can be used in the correct order as intended
        
        # 2. Checksum ICMP packet using given function
        newChecksum = NetworkApplication.checksum(self, headerData)
        # 3. Insert checksum into packet
        header = struct.pack('BBHHH',8,0,newChecksum, ID, 1)
        # 4. Send packet using socket
        send = icmpSocket.sendto(header, (destinationAddress,0))
        # 5. Record time of sending
        ICMPPing.sendTime = time.time()
        pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        ICMPPing.sendOnePing(self, icmpSocket, destinationAddress, ICMPPing.uniqueID)
        # 3. Call receiveOnePing function
        delay = ICMPPing.receiveOnePing(self, icmpSocket, destinationAddress, ICMPPing.uniqueID, 5)
        # 4. Close ICMP socket
        ICMPPing.uniqueID = ICMPPing.uniqueID + 1
        icmpSocket.close()
        # 5. Return total network delay
        return delay
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        ipAddress = socket.gethostbyname(args.hostname)
        print("IP: %s" % ipAddress)
        # 2. Call doOnePing function, approximately every second
        while True:
            delay = ICMPPing.doOnePing(self, ipAddress, 5)
            # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            #version, ihl, tos, total_length, id, flags, ttl, protocol, checksum, source, destination = struct.unpack("!BBHHHBBHII", self.ipHeader)
            #self.printOneResult('1.1.1.1', 50, 20.0, 150) # Example use of printOneResult - complete as appropriate
            #self.printOneResult(ipAddress, totalLen, delay, ttl)
            time.sleep(1)
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))

        ttl = 1

        while True:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            destination = socket.gethostbyname(args.hostname)
            startTime = time.time()

            # Create packet with checksum
            headerData = struct.pack("BBHHH",8,0,0, 1,1)
            newChecksum = NetworkApplication.checksum(self, headerData)
            header = struct.pack('BBHHH',8,0,newChecksum, 1, 1)

            # Send packet to destination
            send = icmpSocket.sendto(header, (destination,0))

            # Recieve reply and compare address with destination
            reply, address = icmpSocket.recvfrom(512)
            rtt = (time.time() - startTime) * 1000
            address = address[0]
            
            try:
                hostname = socket.gethostbyaddr(address)[0]
            except socket.herror:
                #host name error
                hostname = address
    
            if address == destination:
                break

            self.printMultipleResults(ttl, address, (rtt,rtt,rtt), hostname)
            icmpSocket.close()
            ttl = ttl + 1


class ParisTraceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Paris-Traceroute to: %s...' % (args.hostname))

        ttl = 1

        while True:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # Set the socket ttl
            icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            # Get our goal destination from the hostname argument
            destination = socket.gethostbyname(args.hostname)
            port = random.randint(1,65535) # Generate random port number
            
            # Bind socket to port so we can keep the port in flow identifier consistent even with load balancers
            icmpSocket.bind(("",port)) 
            

            # Create packet with checksum - as I did in ping
            # Specifically the string format for struct
            headerData = struct.pack("BBHHH",8,0,0, 1,1)
            newChecksum = NetworkApplication.checksum(self, headerData)
            header = struct.pack('BBHHH',8,0,newChecksum, 1, 1)

            # Set tries to 3 for 3 measurements
            tries = 3

            # Create a list to store delay results
            results = []
            while tries > 0: # Repeat 3 times for 3 delay measurements
                # Send packet to destination
                send = icmpSocket.sendto(header, (destination,port))
                # Record time of sending
                startTime = time.time()
                try:
                    # Recieve reply and compare address with destination
                    reply, address = icmpSocket.recvfrom(512)

                    rtt = (time.time() - startTime) * 1000 # Calculate rtt in milliseconds
                    results.append(rtt) # Append this rtt value to list of results

                    address = address[0] # Get the address from the response
                    tries = tries - 1 # Decrement the number of tries
                except socket.error: # If there is a socket error
                    # Print and reduce tries.
                    print("error")
                    tries = tries - 1
                
            try: # Resolve the hostname using the given address
                hostname = socket.gethostbyaddr(address)[0]
            except socket.herror:
                #host name error, so we use the address as the 'name'
                hostname = address
            
            # Print the results using print multiple results
            self.printMultipleResults(ttl, address, results, hostname)

            # When the current address matches our destination goal, break from the while loop
            if address == destination:
                break

            # Close sockets and increment ttl for the next loop
            icmpSocket.close()
            ttl = ttl + 1
        

class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        message = tcpSocket.recv(1024)

        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        path = message.decode().split()[1]
        # 3. Read the corresponding file from disk
        try:
            # 1: because path starts with a / so this removes the first character in the path message
            # rb means read binary mode so the contents are bytes not text
            with open(path[1:], "rb") as file:
                buffer = file.read()
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
            responseError = b"HTTP/1.1 200 OK"
        except FileNotFoundError:
            responseError = b"HTTP/1.1 404 Not Found"
            buffer = b"File not found"
        # 6. Send the content of the file to the socket
        content = responseError + buffer
        
        tcpSocket.sendall(content)
        # 7. Close the connection socket
        tcpSocket.close()
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % 8080)
        # 1. Create server socket
        host = '' 
        port = 8080

        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Fixes port already in use error
        # SO_REUSEADDR allows server to bind to address and port that is in use by another connection
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 2. Bind the server socket to server address and server port
        serverSocket.bind((host,port))
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(1)

        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        while True:
            clientSocket, clientAddress = serverSocket.accept()
            WebServer.handleRequest(clientSocket)
        # 5. Close server socket
        
        


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % args.port)

        #Create server socket as done in web server
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #create empty cache
        cache = {}

        # bind to configuarble port
        serverSocket.bind(('', args.port))
        serverSocket.listen(1)

        while True:
            # Accept connection and recieve the requested message from client
            clientSocket, clientAddress = serverSocket.accept()
            data = clientSocket.recv(1069)

            # check if the request is in the cache already
            cachedObjects = cache.get(data)

            if cachedObjects is None:
                # if it is not in cache then forward request to web server
                webServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Fixes port already in use error
                # SO_REUSEADDR allows server to bind to address and port that is in use by another connection
                serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # find the destination host from the request
                # see reference at the bottom of proxy
                line = data.split(b'\n')[0]
                url = line.split()[1]
                startPosition = url.find(b'://') + len(b'://')

                endPosition = url.find(b'/', startPosition)

                if endPosition == -1:
                    endPosition = len(url)
                
                destination = url[startPosition:endPosition].decode()

                webServer.connect((destination, 80))
                webServer.sendall(data)

                # get the response message
                response = webServer.recv(4096)

                # cache the response for the future
                cache[data] = response

                # send response to client
                clientSocket.sendall(response)
            else:
                # if cache is empty then grab from data structure
                clientSocket.sendall(cachedObjects)

            clientSocket.close()
            webServer.close()

if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
