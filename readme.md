Team members:  Qikai Lu, Dichong Song

Work distribution:
We designed the algroithm and worked everything together.

Open source code use:
AES encryption function are directly copied from:
https://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes

Instruction:
Sign up: press s in welcome screen to go into sign up page. Input the following messages to sign up:
	cid: customer unique id
	gid: group id (it should also be memerized)
	password: customer password

log in: press l in welcome screen to go into log in page. Input the following messages to log in:
	cid: customer unique id
	gid: group id
	password: customer password

command list for this program ('+' here simply represents space in real. This can help count arguments):
	create directory: cd + dir_name
	delete directory: dd + dir_name
	list current directory:	ld
	get current path:	gd
	move to another directory: md + dir_name (. represents upper directory)
	create file:	cf + file_name 
	delete file:	df + file_name 
	rename file:	nf + old_file_name + new_file_name
	change permission: cp + group_name + file_path + permission(NXRW)
	read file:	rf + file_name + cid(who issues the permission)
	write file:	wf + file_name + cid(who issues the permission)

To run server: python3 server.py port_number server_key(anything you want, just make sure keep it consistent every time you launch)
To run client: python3 client.py port_number
 
