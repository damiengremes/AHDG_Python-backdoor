import socket
import time
import threading
import sys


class inThread(threading.Thread):
    def __init__(self, prod_list,lock):
        super().__init__()
        self.prod_list = prod_list
        self.lock=lock

    def run(self):
        s = socket.socket() #Par défaut, construit un socket TCP
        s.bind(('',4444))
        s.listen(5) #Nb connexions max entre parenthèses

        conn, addr = s.accept() #Renvoie une connexion et l'adresse (Port + IP)

        again = True
        while again:
            msg = conn.recv(1024).decode('UTF-8')  #Taille de buffer entre parenthèses
            if msg == '!quit':
                again = False
            else:
                print(msg)

    def stop(self):
    	s.close()

class outThread(threading.Thread):
    def __init__(self,ip):
        super().__init__()
        self.ip = ip

    def __start__(self):
    	s = socket.socket()

    def sending(self, message):
        again = True
        while again:
            shell = input('{} > shell > '.format(ipaddr))

            s.sendall(message.encode('UTF-8'))

    def stop(self):
    	s.close()




#Begin session

end = False
while not end:
	cmd = input('{} > '.format(ipaddr))
	if cmd ='':
		pass
	elif cmd =='quit':
		s.send
		end = True
	elif cmd =='help':
		help()
	elif cmd =='info':
		get_info()
	elif cmd =='shell':
		shell()
	else:
		help()

#Close session

shell = input('{} > shell > '.format(ipaddr))

print("Test")
#coucou
if len(sys.argv) < 3:
	pass #print help
elif len(sys.argv) == 4:
	pass #do stuff
else:
	pass 
