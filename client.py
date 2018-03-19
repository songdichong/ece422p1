import socket
import sys
import math
import re
from functions_socket import *
from functions_init import *

bufsize = 2048;

class StringMutableWrapper():
    def __init__(self, string):
        self.string = string;

def welcome_screen(conn):
	print("Welcome to secure file saving system!\n");
	smsg = ""
	rmsg = ""

	cid = None
	gid = None
	pwd = None
	while True:
		# for login and sign up please see the accompanying flow diagram for information
		cmd1 = input("Do you want to sign up(s), log in(l), or quit(q)?\n")
		#sign up
		if cmd1 == "s":
			conn.send(cmd1.encode())
			rmsg = conn.recv(bufsize).decode("utf-8")
			if rmsg == "STARTS":
				print("start sign up")

				# Get user information
				###############################################################
				cid = ""
				gid = ""
				pwd = ""
				
				proceed = 0;
				while (proceed == 0):
					cid = input("Please enter the user id (at least 3 char or number):");
					gid = input("Please enter you group id (must be characters or numbers)):");
					if (not re.match("^[A-Za-z0-9_]{3,}$", cid)):
						print("User id not accepted. Retry.");
						continue;
					elif (not re.match("^[A-Za-z0-9_]", gid)):
						print("Group id name not accepted. Retry.");
						continue;
					conn.send((cid + "," + gid).encode());
					isAccepted = conn.recv(bufsize).decode();
					print(isAccepted)
					if (isAccepted == "CAN_REGISTER"):
						proceed = 1;
					elif (isAccepted == "CANNOT_REGISTER"):
						print("User id is not unique. Retry.");
					else:
						print("Error, socket disconnect.");

				proceed = 0
				while (proceed == 0):
					pwd = input("Please enter the password (at least 6 char or num):");
					if (not re.match("^[A-Za-z0-9_]{6,}$", pwd)):
						print("Password not accepted. Retry.")
					else:
						proceed = 1;

				######################################################################
				#create private & public key
				private_key, public_key = createKey()
				print("public & private key created")
				#encrypt pwd with public key
				encrypted_pwd = RSA.importKey(public_key).encrypt(cid_pwdKey(cid, gid, pwd), 32)
				#encrypt private key with cid + pwd
				encrypted_private_key = encryptKey(private_key, cid_pwdKey(cid, gid, pwd))

				# send encrypted pwd
				conn.send(encrypted_pwd[0]);
				if (conn.recv(bufsize).decode() == "PWD"):
					print("Password sent")
				else:
					print("Password not sent") 
				#send public key to server
				conn.send(public_key)
				rmsg = conn.recv(bufsize).decode("utf-8")
				if rmsg == "PUBKY":
					print("already send pub_key")
				else:
					print("error in sending pub_key")
				#send encrypted private key to server
				conn.send(encrypted_private_key)
				
				rmsg = conn.recv(bufsize).decode("utf-8")
				if rmsg == "PRIKY":
					print("already send pri_key")
				else:
					print("error in sending pri_key")
				
				
			else:
				print("sign up encountered unexpected error, will exit");
				sys.exit(1);
			
		#login
		elif cmd1 == "l":
			conn.send(cmd1.encode())
			rmsg = conn.recv(bufsize).decode("utf-8")
			if rmsg == "STARTL":
				cid = input("Please enter user id: ");
				gid = input("Please enter group id: ");
				pwd = input ("Please enter password: ");

				conn.send(cid.encode());
				if (conn.recv(bufsize).decode() == "FOUND"):
					conn.send("PBKEY".encode());
					pbkey = conn.recv(bufsize);
					encrypted_pwd = RSA.importKey(pbkey).encrypt(cid_pwdKey(cid, gid, pwd), 32)
					conn.send(encrypted_pwd[0]);

				else:
					print("Login information not found.")
					continue;

				if (conn.recv(bufsize).decode() == "SUCC"):
					enc_pvkey= conn.recv(bufsize)
					pvkey = decryptKey(enc_pvkey,cid_pwdKey(cid, gid, pwd))
					print("Login success");
					private_key = RSA.importKey(pvkey)
					login_screen(cid, gid, pwd, private_key)
					
				else:
					print("Login failed");
				
			else:
				print("login encountered unexpected error, will exit");
				sys.exit(1);
		
		elif cmd1 == "q":
			conn.send(cmd1.encode())
			if (conn.recv(bufsize).decode()):	
				print("Client will now exit.")
			else:
				print("Improper exit.")
			conn.close()
			break

		else:
			print("Invalid command. Please try again.")
		

def login_screen(cid, gid, pwd, pvkey):

	### receive information on untracked modifications
	print("The following files and folders were noted to have been potentially altered by external users:");
	s.send("NEXT".encode())
	e = s.recv(bufsize).decode();
	while (e != "DONE"):
		print(e);
		s.send("NEXT".encode())
		e = s.recv(bufsize).decode();
	print("----------------------------------------");


	### main loop on command processing
	while (True):
		cmd = input("Please enter command: ");
		smsg = cmd;
		s.send(smsg.encode());
		pcmd = cmd.split(" ");
		###################################################################
		if (pcmd[0] == "cd"): # create directory
			rmsg = s.recv(bufsize).decode("utf-8");
			if(rmsg == "DONE"):
				print("Folder created");
			elif(rmsg == "FAIL"):
				print("Folder failed to create");
			elif (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");

			
		elif (pcmd[0] == "dd"): # delete directory
			rmsg = s.recv(bufsize).decode("utf-8");
			if(rmsg == "DONE"):
				print("Folder deleted");
			elif(rmsg == "FAIL") :
				print("Folder failed to delete");
			elif (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");


		elif (pcmd[0] == "ld"): # list directory (what is in directory)
			rmsg = s.recv(bufsize).decode("utf-8");
			if (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_T"):
				print("Server error");
			else:
				print("These files and directories arefound in the current path:")
				while (rmsg != "DONE"):
					print(rmsg)
					s.send("NEXT".encode());
					rmsg = s.recv(bufsize).decode();
			
			
		elif (pcmd[0] == "gd"): # get directory (get path)
			rmsg = s.recv(bufsize).decode("utf-8");

			if (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_T"):
				print("Server error");
			else:
				print("Current path:")
				print(rmsg);

			
		elif (pcmd[0] == "md"): # create directory (move to a different directory, one step at a time)
			rmsg = s.recv(bufsize).decode("utf-8");
			if (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_T"):
				print("Server error");
			elif (rmsg == "DONE"):
				s.send("PATH".encode());
				rmsg = s.recv(bufsize).decode();
				print("New path:")
				print(rmsg);
			elif (rmsg == "FAIL"):
				print("Cannot move directory, either due to path constraint or incorrect dir name");

		##############################################################
		elif (pcmd[0] == "cf"): # create file
			rmsg = s.recv(bufsize).decode();
			#~ print(rmsg)
			if (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");
			elif (rmsg == "SUCC"):
				sig = form_signature(gid,cid,pvkey)
				s.send(sig);
				rmsg = s.recv(bufsize).decode();
				if(rmsg == "DONE"):
					print("File created");
				elif(rmsg == "FAIL") :
					print("File failed to create");
		
		elif (pcmd[0] == "df"): # delete file
			rmsg = s.recv(bufsize).decode();
			if(rmsg == "DONE"):
				print("File deleted");
			elif(rmsg == "FAIL"):
				print("File failed to delete");
			elif (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");
			
		elif (pcmd[0] == "nf"): # rename file
			rmsg = s.recv(bufsize).decode("utf-8");
			if(rmsg == "DONE"):
				print("File renamed");
			elif(rmsg == "FAIL"):
				print("File failed to rename");
			elif (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");

		elif (pcmd[0] == "cp"): # change permission
			shareto = pcmd[1]
			rmsg = s.recv(bufsize).decode("utf-8");
			if (rmsg == "ERR_M"):
				print("Incorrect command");
			elif (rmsg == "ERR_P"):
				print("Command restricted due to path");
			elif (rmsg == "ERR_T"):
				print("Server error");
			elif (rmsg == "FAIL"):
				print("Failed to change permission");
			elif (rmsg == "SUCC"):
				sig = form_signature(shareto,cid,pvkey)
				s.send(sig);
				rmsg = s.recv(bufsize).decode();
				if(rmsg == "DONE"):
					print("Permisssion changed");
				elif(rmsg == "FAIL") :
					print("File failed to change permission");
			
		elif (pcmd[0] == "rf"): # read file (see server side write file for structure)
			rmsg = s.recv(bufsize) # 1
			try:
				if (rmsg == "ERR_M".encode()):
					print("Incorrect command");
				elif (rmsg == "DENIED".encode()):
					print("Not permitted")
				elif (rmsg == "NOFILE".encode()):
					print("File not found")
				elif (rmsg == "ERR_T".encode()):
					print("Server error");
				else:
					#~ print("In here")
					enc_file_key = rmsg
					file_key = private_key_decryption(pvkey, enc_file_key)
					smsg = "RLEN";
					s.send(smsg.encode("utf-8")); # 2
					rmsg = s.recv(bufsize).decode("utf-8"); #3
					# check that rmsg is a number (maybe cap it?)
					rep = math.ceil(float(rmsg) / bufsize);
					f = b"";
					for i in range(0, rep):
						smsg = "RNEXT";
						s.send(smsg.encode("utf-8")); #4
						#actual contents, decrypt this with file_key
						rmsg = s.recv(bufsize);
						f += rmsg;
					smsg = "RNEXT";
					s.send(smsg.encode("utf-8"));
					rmsg = s.recv(bufsize).decode("utf-8");
					if (rmsg == "NONEXT"):
						print(decryptKey(f,file_key).decode());
			except:
				print("Soemthing went very wrong, was this file modified illegally?");

		elif (pcmd[0] == "wf"): # write file (see server side read file for structure)
			try:
				rmsg  = s.recv(bufsize)
				#check if server sends nofile (can decode) or enc_file_key (cannot decode)
				if (rmsg == "ERR_M".encode()):
					print("Incorrect command");
				elif (rmsg == "DENIED".encode()):
					print("Not permitted")
				elif (rmsg == "NOFILE".encode()):
					print("File not found")
				elif (rmsg == "ERR_T".encode()):
					print("Server error");
				else:
					enc_file_key = rmsg
					file_key = private_key_decryption(pvkey,enc_file_key)
					#actual contents, encrypt this with file_key
					text = ""
					line = input("Input line of text to write (to indicate end of text, press enter directly): \n");
					while (line != ""):
						text += line + "\n";
						line = input("Input line of text to write (to indicate end of text, press enter directly): \n");
						
					enc_message = encryptKey(text.encode(),file_key)
					#~ print(enc_message)
					smsg = str(len(enc_message));
					s.send(smsg.encode("utf-8"));
					for i in range(0, len(enc_message), bufsize):
						rmsg = s.recv(bufsize).decode("utf-8");
						if (rmsg == "WNEXT"):
							if (i > len(enc_message)-bufsize):
								smsg = enc_message[i:];
							else:
								smsg = enc_message[i:i+bufsize];
							s.send(smsg);
						else:
							print("Client did not request further reads");
							break;
					rmsg = s.recv(bufsize).decode("utf-8");
					smsg = "NONEXT";
					s.send(smsg.encode("utf-8"));
					rmsg = s.recv(bufsize).decode("utf-8");
					if (rmsg == "DONE"):
						print("File is written.");
					else:
						print("File failed to write");
			except:
				print("Soemthing went very wrong, was this file modified illegally?");
			
		elif (pcmd[0] == "exit"):
			rmsg = s.recv(bufsize).decode("utf-8");
			print("Now exit");
			break;
			# done
			
		else: # in case of something
			print("Command Unrecognised");
			# done

	print("Client will now exit");

		
if __name__ == "__main__":
	HOST = "localhost"
	PORT = int(sys.argv[1])
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))

	smsg = ""
	rmsg = ""

	welcome_screen(s)
