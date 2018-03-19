from __future__ import division
from multiprocessing import Process
from functions_socket import *
from functions_init import *
import socket
import sys
import hashlib
import math
import os

bufsize = 2048;

class StringMutableWrapper():
    def __init__(self, string):
        self.string = string;

class BytesMutableWrapper():
    def __init__(self, bstring):
        self.bstring = bstring;

def welcome_screen(db_path,conn,addr, sk_hash):
	connect(db_path)
	
	print("Welcome to secure file saving system!");
	smsg = ""
	rmsg = ""
	
	while True:
		mode = conn.recv(bufsize).decode()
		
		if mode == "s":
			print(mode);
			conn.send("STARTS".encode())
			#######################################
			while True:
				(cid, gid) = conn.recv(bufsize).decode().split(",");
				if (check_unique(cid)):
					conn.send(("CAN_REGISTER").encode())
					break
				else:
					conn.send(("CANNOT_REGISTER").encode())

			pwd = conn.recv(bufsize)
			conn.send("PWD".encode())
			
			public_key = conn.recv(bufsize)
			conn.send("PUBKY".encode())
				
			private_key = conn.recv(bufsize)
			conn.send("PRIKY".encode())

			# register the user			
			print("sign up successful")
			register(cid, gid, pwd, public_key, private_key);
			path = str(sys.path[0]) + "/root/members/" + gid + "/" + cid
			createDir(path);
			insert_dirpath(path, hashDir(path, cid.encode()))

			#################################################

			
		elif mode == "l":
			smsg = "STARTL"
			conn.send(smsg.encode())

			###################################################
			cid = conn.recv(bufsize).decode("utf-8");

			(cid, gid, encrypted_pwd, pbkey, encrypted_pvkey) = find_row(cid);

			if (encrypted_pvkey != None and encrypted_pwd != None):
				conn.send("FOUND".encode());
				PBKEY = conn.recv(bufsize).decode("utf-8");
				conn.send(pbkey);
				client_pwd = conn.recv(bufsize);
				
				if (encrypted_pwd == client_pwd):
					conn.send("SUCC".encode());
					group_key = hashlib.sha256(sk_hash+gid.encode()).digest()			
					publickey = RSA.importKey(pbkey)
					conn.send(encrypted_pvkey)
					
					proc(conn, addr, gid, cid, sk_hash, publickey, group_key)
				else:
					conn.send("FAIL".encode());
				
			else:
				conn.send("ERR".encode());
			#################################################
			
		elif mode == "q":
			print("This process will now close")
			# send something in response!
			conn.send("CLOSED".encode());
			conn.close()
			break

		elif mode == "":
			print("Socket disconnect. WIll close current process.")
			break;
			
		else:
			print("Invalid command. Please try again.")

def proc(conn, addr, gid, cid, sk_hash, pbkey, group_key):
	print("New process started");
	curr_path = StringMutableWrapper(str(sys.path[0]) + "/root/members/" + gid + "/" + cid); # initial home directory
	lim_path = str(sys.path[0]) + "/root/members" # do not back up further than this
	def_path = str(sys.path[0]) + "/root/members/" + gid  + "/" + cid # do not delete anything starting from this folder

	### checking for untracked modification
	err = [];
	checkDirFile(curr_path.string, cid.encode(), err);
	if (err != []):
		for e in err:
			conn.recv(bufsize).decode();
			conn.send(decP(e, def_path).encode());
	conn.recv(bufsize).decode();
	conn.send("DONE".encode());

	prmsg = [];
	
	while (True):
		rmsg = conn.recv(bufsize).decode("utf-8");
		print(rmsg)
		prmsg = rmsg.split(" ");
		## in general, for all functions in sfunctions, 1 is a sucess, 0 is a fail, anything else is an error

		# directory based actions
		##################################################
		# create directory (tested, passed)
		if (prmsg[0] == "cd"):
			try:
				if (len(prmsg) != 2):
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue

				dirpath = curr_path.string + "/" + encFD(prmsg[1]);
				if createDir(dirpath) == 1:
					smsg = "DONE"
					insert_dirpath(dirpath, hashDir(dirpath, cid.encode()))
					rehash_dirpath(curr_path.string, hashDir(curr_path.string, cid.encode()))
				else:
					smsg = "FAIL"
				smsg = conn.send(smsg.encode());
			except:
				conn.send("ERR_T".encode());


		# delete directory (tested, passed)
		elif (prmsg[0] == "dd"):
			try:
				if (len(prmsg) != 2):
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue
				
				dirpath = curr_path.string + "/" + encFD(prmsg[1]);
				if deleteDir(dirpath) == 1:
					smsg = "DONE";
					delete_dirpath(dirpath)
					rehash_dirpath(curr_path.string, hashDir(curr_path.string, cid.encode()))
				else:
					smsg = "FAIL"
				conn.send(smsg.encode());
			except:
				conn.send("ERR_T".encode());

		# list content of directory (tested, path)
		elif (prmsg[0] == "ld"):
			try:
				if (len(prmsg) != 1):
					conn.send("ERR_M".encode());
					continue
				
				for d in os.listdir(curr_path.string):
					conn.send(decFD(d).encode());
					print(conn.recv(bufsize).decode()); # NEXT
				conn.send("DONE".encode());
			except:
				conn.send("ERR_T".encode());

		# get directory path (tested, path)
		elif (prmsg[0] == "gd"):
			try:
				if (len(prmsg) != 1):
					conn.send("ERR_M".encode());
					continue
				
				conn.send(decP(curr_path.string, lim_path).encode());
			except:
				conn.send("ERR_T".encode());

		# set new directory (tested, path)
		elif (prmsg[0] == "md"):
			try:
				if (len(prmsg) != 2):
					conn.send("ERR_M".encode());
					continue
					
				if (prmsg[1] in [gid, cid, "."] or has_gid(prmsg[1]) or find_row(prmsg[1]) != (None, None, None, None, None)):
					dirname = prmsg[1];
				else:
					dirname = encFD(prmsg[1])
				cond = changeDir(curr_path, dirname, lim_path);
				if (cond == 1):
					conn.send("DONE".encode());
					getpath = conn.recv(bufsize).decode();
					conn.send(decP(curr_path.string, lim_path).encode());
				else:
					conn.send("FAIL".encode());
			except:
				conn.send("ERR_T".encode());

		# file based operations
		############################
		# create file (tested)
		elif (prmsg[0] == "cf"):
			try:
				if (len(prmsg) != 2):
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue
				else:
					conn.send("SUCC".encode());
				filepath = curr_path.string + "/" + encFD(prmsg[1]);
				cond = createFile(filepath, b"");
				if (cond == 1):
					file_key = encrypt_password(randomFileKey());
					#~ print("filekey: ",file_key)
					enc_file_key = encryptKey(file_key, group_key);
					signature = conn.recv(bufsize)
					insert_filepath(gid, cid, filepath, "R", signature, enc_file_key, hashFile(filepath, cid.encode()));
					rehash_dirpath(curr_path.string, hashDir(curr_path.string, cid.encode()));
					conn.send("DONE".encode());
				else:
					conn.send("FAIL".encode());
			except:
				conn.send("ERR_T".encode());
			

		# delete file (tested)
		elif (prmsg[0] == "df"):
			try:
				if (len(prmsg) != 2):
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue
					
				filepath = curr_path.string + "/" + encFD(prmsg[1]);
				delete_filepath(filepath);
				rehash_dirpath(curr_path.string, hashDir(curr_path.string, cid.encode()))
				cond = deleteFile(filepath);
				if (cond == 1):
					conn.send("DONE".encode());
				else:
					conn.send("FAIL".encode());
			except:
				conn.send("ERR_T".encode());				

		# rename file (tested)
		elif (prmsg[0] == "nf"):
			try:
				if (len(prmsg) != 3):
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue
					
				oldname = curr_path.string + "/" + encFD(prmsg[1]);
				newname = curr_path.string + "/" + encFD(prmsg[2]);
				rename_filepath(oldname, newname);
				rehash_dirpath(curr_path.string, hashDir(curr_path.string, cid.encode()))
				if (renameFile(oldname, newname)):
					conn.send("DONE".encode());
				else:
					conn.send("FAIL".encode());
			# done
			except:
				conn.send("ERR_T".encode());

		# change permission (tested)
		elif (prmsg[0] == "cp"):
			try:
				if (len(prmsg) != 4): # cmd, shareto, file-in-curr_path, permission
					conn.send("ERR_M".encode());
					continue
				elif (not curr_path.string.startswith(def_path)):
					conn.send("ERR_P".encode());
					continue
				

				shareto = prmsg[1];
				filepath = curr_path.string + "/" + encFD(prmsg[2]);
				permission = prmsg[3];
				if (not has_filepath(filepath) or not has_gid(shareto)):
					conn.send("FAIL".encode());
					continue;
					
				conn.send("SUCC".encode())				
				sig = conn.recv(bufsize);
				change_permission(shareto, cid, filepath, permission, sig);
				conn.send("DONE".encode());
				
			except:
				conn.send("ERR_T".encode());

		# read file (work on concurrent access via synchronization objects)
		elif (prmsg[0] == "rf"):
			# operation works by first accepting the length of the string read, then send it in chunks of bufsize bytes via stop-wait synchrnous communication
			try:
				if (len(prmsg) != 3): # cmd, shareto, file-in-curr_path, permission
					conn.send("ERR_M".encode());
					continue
				
				dirpath = curr_path.string + "/" + encFD(prmsg[1]);
				cfid = prmsg[2];

				if (check_permission(gid, cfid, dirpath) not in ["R", "X"] and cfid != cid):
					conn.send("DENIED".encode());
					continue
				
				smw = BytesMutableWrapper(b""); # makes the "string" mutable
				if (readFile(dirpath, smw) == 1):
					#send enc_file_key to user
					enc_file_key = select_filekey(dirpath)
					file_key = decryptKey(enc_file_key, hashlib.sha256(sk_hash+find_row(cfid)[1].encode()).digest())
					#~ print(file_key)
					pub_file_key = public_key_encryption(pbkey,file_key)
					#~ print(pub_file_key)
					conn.send(pub_file_key) # 1
					rmsg = conn.recv(bufsize).decode("utf-8"); # 2
					if (rmsg == "RLEN"): # client should ask for length of content
						smsg = str(len(smw.bstring)); # send string len
						conn.send(smsg.encode("utf-8")); #3
						for i in range(0, len(smw.bstring), bufsize): # send the file content (stored as string) in chunks, socket buffer is the limit
							rmsg = conn.recv(bufsize).decode("utf-8") #4;
							if (rmsg == "RNEXT"):
								if (i > len(smw.bstring)-bufsize):
									smsg = smw.bstring[i:];
								else:
									smsg = smw.bstring[i:i+bufsize];
								conn.send(smsg);
							else:
								print("Client did not request further reads"); # something went wrong
								break;
						rmsg = conn.recv(bufsize).decode("utf-8"); # client will send an extra RNEXT, to make sure that everything is read (else, some interception or loss of data has occurred)
						smsg = "NONEXT";
						conn.send(smsg.encode("utf-8")); # alert client that everything is sent
				else: # file not found
					conn.send("NOFILE".encode());
					pass; # do nothing, be explicit
			except:
				conn.send("ERR_T".encode());

		# write file
		elif (prmsg[0] == "wf"):
			try:
				if (len(prmsg) != 3): # cmd, shareto, file-in-curr_path, permission
					conn.send("ERR_M".encode());
					continue
				
				dirpath = curr_path.string + "/" + encFD(prmsg[1]);
				cfid = prmsg[2];

				if (check_permission(gid, cfid, dirpath) not in ["W", "X"] and cfid != cid):
					conn.send("DENIED".encode());
					continue
					
				print("Write file: " + dirpath);
				if (hasFile(dirpath) == 1): # make sure file exists 
					#send enc_file_key to user
					enc_file_key = select_filekey(dirpath)
					file_key = decryptKey(enc_file_key, hashlib.sha256(sk_hash+find_row(cfid)[1].encode()).digest())
					pub_file_key = public_key_encryption(pbkey,file_key)
					conn.send(pub_file_key)
					# to request length
					rmsg = conn.recv(bufsize).decode("utf-8")
					# check that this is a integer string
					rep = math.ceil(float(rmsg) / bufsize); # change length into number of chunks (iteration for reading)
					smw = BytesMutableWrapper(b""); # for temp storing the string
					for i in range(0, rep): # works on a request in iteration method,
						smsg = "WNEXT";
						conn.send(smsg.encode("utf-8"));
						rmsg = conn.recv(bufsize);
						smw.bstring += rmsg; # store the string section
					smsg = "WNEXT"; # extra WNEXT, make sure that the string length is agreed by both client and server
					conn.send(smsg.encode("utf-8"));
					rmsg = conn.recv(bufsize).decode("utf-8");
					if (rmsg == "NONEXT"): # this should be the case, as no error has occurred then
						if(writeFile(dirpath, smw) == 1): # write file
							rehash_filepath(dirpath, hashFile(dirpath, cid.encode()));
							conn.send("DONE".encode());
						else:
							conn.send("FAIL".encode());
				else:
					smsg = "NOFILE";
					conn.send(smsg.encode("utf-8"));

			except:
				conn.send("ERR_T".encode());	

		
		elif (prmsg[0] == "exit"):
			print("Exiting");
			smsg = "EACK";
			conn.send(smsg.encode());
			break;
			#done
		elif (prmsg[0] == ""):
			print("Disconnected");
			break;
		else:
			print("Command Unrecognised");
			#done

	print("This process will now close");
	#~ conn.close();
	
	
if (__name__ == "__main__"):
	##################################
	sk_hash = hashString(sys.argv[2]);
	#~ print(sk_hash)
	
	print("File Server System now operational:");

	# directory setup
	folders = ["root", "root/database", "root/members"];
	for f in folders:
		if (not os.path.exists(str(sys.path[0]) + "/" + f)):
			os.makedirs(str(sys.path[0]) + "/" + f);
	files = ["root/database/ece422proj1.db"];
	for f in files:
		if (not os.path.exists(str(sys.path[0]) + "/" + f)):
			fd = open(str(sys.path[0]) + "/" + f, "wb");
			fd.close();
			connect(str(sys.path[0]) + "/" + f);
			initialise(str(sys.path[0]) + "/" + f, str(sys.path[0]) + "/tables.sql");
	
	HOST = "localhost";
	PORT = int(sys.argv[1]);
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
	s.bind((HOST, PORT));
	s.listen(1);
	
	while (True):
		
		(conn, addr) = s.accept();
		p = Process(target=welcome_screen, args=(str(sys.path[0]) + '/root/database/ece422proj1.db', conn, addr, sk_hash));
		p.start();

