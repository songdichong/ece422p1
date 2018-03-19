import os
import shutil
import errno
import random
import hashlib
import sys
import sqlite3
import re
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from functions_init import *

# file operations
def createFile(user_path_file,context=b""):
	if os.path.exists(user_path_file):
		print("The file with current name has already exists.\nPlease change to another name.")
		return 0
	else:
		with open(user_path_file, "wb") as f:
			f.write(context)
		f.close()
		return 1

def deleteFile(user_path_file):
	if os.path.exists(user_path_file):
		os.remove(user_path_file)
		return 1
	else:
		print("The file with current name does not exist.")
		return 0

def hasFile(user_path_file):
	if os.path.exists(user_path_file):
		print("File exist.")
		return 1
	else:
		print("File not found.")
		return 0


def renameFile(user_path_file, new_filename):
	if os.path.exists(user_path_file):
		os.rename(user_path_file, new_filename);
		print("File renamed");
		return 1
	else:
		print("File cannot be found");
		return 0

def readFile(user_path_file, stringwrapper):
	if os.path.exists(user_path_file):
		f = open(user_path_file,"rb")
		contents = f.read()
		f.close()
		stringwrapper.bstring = contents
		return 1
	else:
		print("The file with current name does not exist.")
		return 0

def writeFile(user_path_file, context):
	if os.path.exists(user_path_file):
		f = open(user_path_file,"wb")
		f.write(context.bstring)
		print ("Successful writing of fie content")
		f.close()
		return 1
	else:
		print("The file with current name does not exist.")
		return 0
	

#acknowledgement: The knowledge of encrypting/decrypting a file is learned and mostly copied from
#https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
#with some necessary changes
def encrypt_file(key, in_filename, out_filename=None):
	""" Encrypts a file using AES (CBC mode) with the
		given key.

		key:
			The encryption key - a string that must be
			either 16, 24 or 32 bytes long. Longer keys
			are more secure.

		in_filename:
			Name of the input file

		out_filename:
			If None, '<in_filename>.enc' will be used.

		chunksize:
			Sets the size of the chunk which the function
			uses to read and encrypt the file. Larger chunk
			sizes can be faster for some files and machines.
			chunksize must be divisible by 16.
	"""
	if not out_filename:
		out_filename = in_filename + '.enc'
	
	chunksize=64*1024
	iv=os.urandom(16)
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = str(os.path.getsize(in_filename)).zfill(16)

	with open(in_filename, 'rb') as infile:
		with open(out_filename, 'wb') as outfile:
			outfile.write(filesize.encode())
			outfile.write(iv)

			while True:
				try:
					chunk = infile.read(chunksize).decode()
				except UnicodeDecodeError:
					chunk = infile.read(chunksize)
					
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += ' ' * (16 - len(chunk) % 16)

				outfile.write(encryptor.encrypt(chunk))
	outfile.close()

def decrypt_file(key, in_filename, out_filename=None):
	""" Decrypts a file using AES (CBC mode) with the
		given key. Parameters are similar to encrypt_file,
		with one difference: out_filename, if not supplied
		will be in_filename without its last extension
		(i.e. if in_filename is 'aaa.zip.enc' then
		out_filename will be 'aaa.zip')
	"""
	if not out_filename:
		out_filename = os.path.splitext(in_filename)[0]
	chunksize=64*1024
	with open(in_filename, 'rb') as infile:
		try:
			origsize = infile.read(16)
			iv = infile.read(16)
			decryptor = AES.new(key, AES.MODE_CBC, iv)
			with open(out_filename, 'wb') as outfile:
				while True:
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break

					outfile.write(decryptor.decrypt(chunk))
				outfile.truncate(int(origsize))
				
		except ValueError:
			#Maybe add a fail flag and handle the case of failure in future
			print("decyption fails! Maybe your file has been hacked and changed")
			return

### Dir operation
def createDir(user_path_dir):
	if not os.path.exists(user_path_dir):
		try:
			os.makedirs(user_path_dir)
			return 1
		except OSError as exc: # Guard against race condition
			if exc.errno != errno.EEXIST:
				raise
	else:
		pass
	return 0

def deleteDir(user_path_dir):
	if os.path.exists(user_path_dir):
		try:
			if (os.listdir(user_path_dir) == []):
				os.rmdir(user_path_dir);
				return 1
			else:
				return 0
		except OSError as exc: # Guard against race condition
			if exc.errno != errno.EEXIST:
				raise
	else:
		return -1
		
def changeDir(curr_dir, imm_path, base_dir): # imm_path only works for directories immediately above or below
											# curr_path is str(sys.path[0]); is string wrapper
											# base_dir is the members folder, do not go before this
	if (imm_path == "."):
		if (curr_dir.string == base_dir):
			#~ print("This is the highest directory level accessible");
			return 0; # highest accessible level
		else:
			curr_dir.string = curr_dir.string[:curr_dir.string.rfind("/", 0, len(curr_dir.string))];
			return 1;
	elif (imm_path.count("/") == 0 and not re.match("[.]{2,}", imm_path)):
		if (os.path.exists(curr_dir.string + "/" + imm_path) and os.path.isdir(curr_dir.string + "/" + imm_path)): # goto next
			curr_dir.string += "/" + imm_path;
			return 1;
		else:
			#~ print("Error, directory not found");
			return 0;
	else:
		#~ print("Error, imm_path incorrect");
		return 0;


### intrusion detection
def hashDir(curr_dir, init): # init is in bytes
	#~ print("New launch: " + curr_dir + str(os.listdir(curr_dir)))
	digest = hashBytes(init);
	obj_list = os.listdir(curr_dir);
	obj_list.sort();
	for obj in obj_list:
		digest += hashBytes(obj.encode() + digest)
	return hashBytes(digest);
		   
def hashFile(filepath, init):
	blksize = 2048;
	digest = hashBytes(init);
	with open(filepath, "rb") as fd:
		chunk = fd.read(blksize);
		while (chunk != b""):
			#~ print(chunk);
			digest += hashBytes(chunk + digest);
			chunk = fd.read(blksize);
	return digest;


def checkDirFile(curr_dir, init, errlog = []):
	#~ print("New launch: " + curr_dir)
	digest = hashBytes(init);
	if (hashDir(curr_dir, init) != get_dirpath(curr_dir)[1]):
		errlog.append(curr_dir);
	for obj in os.listdir(curr_dir):
		if (os.path.isdir(os.path.join(curr_dir, obj))):
			checkDirFile(os.path.join(curr_dir, obj), init, errlog);
		elif (os.path.isfile(os.path.join(curr_dir, obj))):
			if (hashFile(os.path.join(curr_dir, obj), init) != get_filepath(os.path.join(curr_dir, obj))[2]):
				errlog.append(os.path.join(curr_dir, obj));
		else:
			pass;
	return errlog;

def encFD(name):
	name = name.split(".");
	if (len(name) == 2):
		return base64.b64encode(name[0].encode()).decode().replace("/", "_") + "." + name[1];
	elif (len(name) == 1):
		return base64.b64encode(name[0].encode()).decode().replace("/", "_");
	else:
		return None

def decFD(name):
	n = name.split(".");
	#~ print(n)
	try:
		if (len(n) == 2):
			return base64.b64decode(n[0].replace("_", "/").encode()).decode() + "." + n[1];
		elif (len(n) == 1):
			return base64.b64decode(n[0].replace("_", "/").encode()).decode();
		else:
			return name;
	except:
		return name;
	
def encP (path, lim): 
	epath = lim;
	parts = path[len(lim):].split("/");
	for p in parts:
		if (p == ""):
			continue
		epath += "/" + encFD(p);
	return epath

def decP (epath, lim): # lim will not be encrypted, epath = lim + enc_section
	path = lim;
	parts = epath[len(lim):].split("/");
	for p in parts:
		if (p == ""):
			continue
		path += "/" + decFD(p);
	return path

if __name__ == "__main__":
	connect(sys.path[0] + '/root/database/ece422proj1.db')
	a = hashDir(str(sys.path[0] + "/root/members/g1"), "qikai".encode());
	#~ print(a);
	el = checkDirFile(str(sys.path[0] + "/root/members/g1"), "qikai".encode());
	for i in el:
		print(i);

	a = (encFD("aaaaa"))
	b = (encFD("aaaaa.txt"))
	print(a)
	print(b)

	a = (decFD(a))
	b = (decFD(b))

	print(a)
	print(b)

	lim = "root/members/g1/qikai"
	path = "root/members/g1/qikai/tasks/numbers/a.txt"
	a = encP(path, lim);
	print(a)
	a = decP(a, lim);
	print(a)
	
	lim = "root/members/g1/qikai"
	path = "root/members/g1/qikai/tasks/numbers/a.txt"
	a = encP(lim, lim);
	print(a)
	a = decP(a, lim);
	print(a)
