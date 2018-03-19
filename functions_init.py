import os
import shutil
import errno
import random
import hashlib
import sys
import sqlite3
import re
from Crypto import Random
from functions_socket import * 
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import random
connection = None

def connect(path):
	global connection

	connection = sqlite3.connect(path)
	cursor = connection.cursor()
	cursor.execute('PRAGMA foreign_keys=ON; ')
	connection.commit()
	cursor.close()
	return

def initialise(path, script):
	global connection
	cursor = connection.cursor();
	with open(script, "r") as fd:
		query = "";
		l = fd.readline();
		while (l != ""):
			query += l;
			l = fd.readline();
	for q in query.split(";"):
		if (q != ""):
			cursor.execute(q);
	connection.commit();
	cursor.close();
	connection.close();
	print("DB initialised.")
			 
def check_unique(cid):
	global connection
	cursor = connection.cursor();
	cursor.execute("SELECT cid FROM customers c WHERE c.cid = '{0}';".format(cid))
	result = cursor.fetchone()
	cursor.close();
	return result is None

def find_row(cid):
	global connection
	cursor = connection.cursor();
	cursor.execute("select * from customers c where c.cid = '{0}'".format(cid));
	row = cursor.fetchone();
	cursor.close();
	if (row != None):
		return row;
	else:
		return (None, None, None, None, None);

def register(cid,group,pwd,public_key,private_key):
	global connection
	cursor = connection.cursor();
	data = (cid,group,pwd,public_key,private_key)
	cursor.execute("INSERT INTO customers(cid,group_name,pwd,public_key,private_key) VALUES (?,?,?,?,?);", data)
	connection.commit()
	cursor.close();
	return

def has_gid(gid): 
	global connection
	cursor = connection.cursor();
	cursor.execute("SELECT * FROM customers c WHERE group_name = '{0}';".format(gid));
	result = cursor.fetchone();
	cursor.close()
	return result is not None

def encrypt_password(password):
	alg = hashlib.sha256()
	alg.update(password.encode('utf-8'))
	return alg.digest()


def createKey():
	key = RSA.generate(1024)
	private_key = key.exportKey('PEM')
	public_key = key.publickey().exportKey('PEM')
	return private_key, public_key

def randomFileKey():
	return str(random.StrongRandom().randint(1, 10000000))

def cid_pwdKey(cid, gid, pwd):
	return hashlib.sha256((cid+gid+pwd).encode('utf-8')).digest()

def cid_pwd_pathKey(cid,gid,pwd,path):
	return hashlib.sha256((cid+gid+pwd+path).encode('utf-8')).digest()

def hashString(string):
	return hashlib.sha256((string).encode('utf-8')).digest()

def hashBytes(bstring):
	return hashlib.sha256((bstring)).digest()

# From https://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes
#################
def pad(s):
	return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encryptKey(message, password, key_size=256):
	message = pad(message)
	iv = Random.new().read(AES.block_size)
	cipher = AES.new(password, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(message)

def decryptKey(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")
########################

# Signatures
def permi_hash(shareto, sharefrom, filepath):
	return hashlib.sha256((shareto+sharefrom+filepath).encode('utf-8')).digest()

def form_signature(shareto, sharefrom, pvkey): # client side only
	phash = SHA.new((shareto + sharefrom).encode());
	signer = PKCS1_PSS.new(pvkey);
	return signer.sign(phash) # ciphertext (text,)

def getPrivateKey(cid):
	global connection
	cursor = connection.cursor()
	cursor.execute("select private_key from customers where cid = '{0}'".format(cid))
	result = cursor.fetchone()[0]
	cursor.close();
	return result

def check_signature(signature, shareto, sharefrom):
	global connection, cursor
	cursor = connection.cursor()
	cursor.execute("select public_key from  customers where cid = '{0}'".format(sharefrom));
	pbkey = cursor.fetchone()[0];
	phash = SHA.new((shareto + sharefrom).encode());
	verifier = PKCS1_PSS.new(RSA.importKey(pbkey));
	return verifier.verify(phash, signature);

# Permission types:
# R read only
# W write only
# X read and write
# N do not do anythin (not in database)
def change_permission(shareto, sharefrom, filepath, permission, signature):
	global connection
	cursor = connection.cursor();
	cursor.execute("select * from permissions p where p.shareto = '{0}' and p.sharefrom = '{1}' and p.filepath = '{2}'; ".format(shareto, sharefrom, filepath));
	result = cursor.fetchone();
	
	if (permission in ['R', 'W', 'X']):
		if (result == None):
			cursor.execute(
			"INSERT INTO permissions(shareto,sharefrom,filepath,permission,signature) VALUES (?,?,?,?,?);",(shareto, sharefrom, filepath, permission,signature))
		else:
			cursor.execute(
			"update permissions set permission = '{0}', signature = ? where shareto = '{1}' and sharefrom = '{2}' and filepath = '{3}';".format(permission, shareto, sharefrom, filepath), (signature, ));
	elif (permission in ['N']):
		if (result != None):
			cursor.execute("delete from permissions where shareto = '{0}' and sharefrom = '{1}' and filepath = '{2}'; ".format(shareto, sharefrom, filepath));

	connection.commit();
	#~ print("Permission changed")
	cursor.execute("select permission, signature from permissions p where p.shareto = '{0}' and p.sharefrom = '{1}' and p.filepath = '{2}'; ".format(shareto, sharefrom, filepath));
	print(cursor.fetchone());


def check_permission(shareto, sharefrom, filepath):
	global connection
	cursor = connection.cursor();
	cursor.execute("select permission, signature from permissions p where p.shareto = '{0}' and p.sharefrom = '{1}' and p.filepath = '{2}'; ".format(shareto, sharefrom, filepath));
	entry = cursor.fetchone();
	if (entry != None):
		if (check_signature(entry[1], shareto, sharefrom)):
			return entry[0];
		else:
			print("Incorrect signature");
			# clean up
			return 'N'
	else:
		return 'N'

## files table access
def insert_filepath(shareto, sharefrom, path, permission, signature, enc_file_key, filehash=None):
	global connection
	cursor = connection.cursor()
	cursor.execute("INSERT INTO files(filepath, filekey, filehash) VALUES (?,?,?);", (path,enc_file_key,filehash))
	cursor.execute("INSERT INTO permissions(shareto, sharefrom, filepath, permission, signature) VALUES (?,?,?,?,?);", (shareto,sharefrom, path, permission, signature))
	connection.commit()
	cursor.close()

def delete_filepath(path):
	global connection
	cursor = connection.cursor();
	cursor.execute("DELETE FROM files WHERE filepath = '{0}';".format(path))
	cursor.execute("DELETE FROM permissions WHERE filepath = '{0}';".format(path)) # test this
	connection.commit()
	cursor.close()

def has_filepath(path):
	global connection
	cursor = connection.cursor();
	cursor.execute("SELECT * FROM files f WHERE filepath = '{0}';".format(path));
	result = cursor.fetchone();
	cursor.close()
	return result is not None

def rename_filepath(old_path, new_path): # old_path and new_path are only renames of the file, and does not indicate actual path change 
	global connection
	
	if (has_filepath(old_path)):
		cursor = connection.cursor();
		cursor.execute("UPDATE files SET filepath = '{0}' WHERE filepath = '{1}';".format(new_path, old_path));
		cursor.execute("UPDATE permissions SET filepath = '{0}' WHERE filepath = '{1}';".format(new_path, old_path));
		connection.commit();
		cursor.close()
		return 1
	else:
		return 0

def rehash_filepath(path, filehash):
	global connection
	
	if (has_filepath(path)):
		cursor = connection.cursor();
		cursor.execute("UPDATE files SET filehash = ? WHERE filepath = ?;", (filehash, path));
		connection.commit();
		cursor.close()
		return 1
	else:
		return 0

def get_filepath(path):
	global connection
	
	if (has_filepath(path)):
		cursor = connection.cursor();
		cursor.execute("SELECT * FROM files WHERE filepath = '{0}';".format(path));
		result = cursor.fetchone()
		cursor.close()
		if (result != None):
			return result
		else:
			return (None, None, None)
	else:
		return (None, None, None)

### dir table access:
	
def insert_dirpath(path, dirhash=None):
	global connection
	cursor = connection.cursor()
	cursor.execute("INSERT INTO dirs (dirpath, dirhash) VALUES (?,?);", (path, dirhash))
	connection.commit()
	cursor.close()

def delete_dirpath(path):
	global connection
	cursor = connection.cursor();
	cursor.execute("DELETE FROM dirs WHERE dirpath = '{0}';".format(path))
	connection.commit()
	cursor.close()

def has_dirpath(path):
	global connection
	cursor = connection.cursor();
	cursor.execute("SELECT * FROM dirs f WHERE dirpath = '{0}';".format(path));
	result = cursor.fetchone();
	cursor.close()
	return result is not None

def rehash_dirpath(path, dirhash):
	global connection
	
	if (has_dirpath(path)):
		cursor = connection.cursor();
		cursor.execute("UPDATE dirs SET dirhash = ? WHERE dirpath = ?;", (dirhash, path));
		connection.commit();
		cursor.close()
		return 1
	else:
		return 0

def get_dirpath(path):
	global connection
	
	if (has_dirpath(path)):
		cursor = connection.cursor();
		cursor.execute("SELECT * FROM dirs WHERE dirpath = '{0}';".format(path));
		result = cursor.fetchone()
		cursor.close()
		if (result != None):
			return result
		else:
			return (None, None)
	else:
		return (None, None)

		
############################################
def select_filekey(path):
	global connection,cursor
	cursor = connection.cursor()
	cursor.execute("select filekey from files where filepath = '{0}';".format(path))
	connection.commit()
	result = cursor.fetchone()
	return result[0]

def public_key_encryption(public_key,plaintext):
	cipher = PKCS1_OAEP.new(public_key)
	ciphertext = cipher.encrypt(plaintext)
	return ciphertext

def private_key_decryption(private_key,ciphertext):
	cipher = PKCS1_OAEP.new(private_key)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext

if __name__ == "__main__":
	#createFile('/home/songdichong/ece422/song/1.txt','hello world')
	connect('ece422proj1.db')
	cid = 'song'
	gid = 'g1'
	pwd = '123456'
	path = './root/members/g1'

	connect(str(sys.path[0]) + "/root/database/ece422proj1.db")
	print(check_permission("g1","qikai", str(sys.path[0]) + "/root/members/g1/qikai/e.txt"));
	print(check_permission("g2","qikai", str(sys.path[0]) + "/root/members/g1/qikai/e.txt"));
	
	#~ print(enc_file_key)
	#~ print(decryptKey(enc_file_key,cid_pwd_pathKey(cid, gid, pwd,path)))
	#insert_filepath(path,enc_file_key)
	#encrypt_file(file_key,'/home/songdichong/ece422/song/1.txt')
	#decrypt_file(key,'/home/songdichong/ece422/1.txt.enc')
	
	#~ enc_pri_key =  getPrivateKey(cid)
	#~ pvkey = decryptKey(enc_pri_key, cid_pwdKey(cid, gid, pwd));
	#~ print(pvkey)
	#~ c = form_signature("kevin", cid, path, pvkey)
	#~ r = check_signature(c, "kevin", cid, path)
	#~ print(r)
	
	#~ c = form_signature("kevin", "qikai", "./root/members/qikaiqikai/qikai");
	#~ print(c)
	#~ r = check_signature(c, "kevin", "qikai", "./root/members/qikaiqikai/qikai")
	#~ print(r);
	#~ change_permission("kevin", "qikai", "./root/members/qikaiqikai/qikai", "W");
	#~ print(check_permission("kevin", "qikai", "./root/members/qikaiqikai/qikai"));
