from logging.config import valid_ident
import time
import pickle   
from Block import Block
import os
from hashing import *
import datetime
import json
from util import *
from network import Node
import sys
import copy
from FullNode import FullNode

			
"""
DO NOT EDIT ANYTHING BELOW
"""
def commands():
	"""
	CLI to access the Blockchain class
	"""
	print("\"update_UTXO\" to update your UTXO database according to the blocks in your valid chain")
	print("\"mine\" to mine")
	print("\"validate\" to validate pending chains")
	print("\"ra\" to request all chains")
	print("\"rl\" to request longest chain")
	print("\"send state\" to send your current state to the backend")
	print("\"print\" to print saved chain")
	print("\"showAccounts\" to print all Accounts Balance")
	print("\"exit\" to exit")
	print("\"help\" to see available commands")
	
if __name__ == "__main__":	
	"""
	Establishing connection with backend
	"""
	host='localhost'
	backend_p=3211

	backend=(host,backend_p)
	try:
		id= os.getlogin()[1:]
		port = int(id[0:2]+id[-3:])
	except:
		print("Invalid ID")
		sys.exit()
	"""
	Node connection setup 
	"""
	node=Node(host,port,backend, id)
	node.start_connection()
	commands()
	N = FullNode(id)
	N.valid_chain, N.confirmed_transactions = load_valid_chain()
	N.unconfirmed_transactions = load_unconfirmed_transactions(N.confirmed_transactions, N.corrupt_transactions)
	N.all_unconfirmed_transactions = load_all_unconfirmed_transactions(N.confirmed_transactions, N.corrupt_transactions)
	node.send_states()
	while True:
		
		args=input(">> ")
		N.valid_chain, N.confirmed_transactions = load_valid_chain()
		N.unconfirmed_transactions = load_unconfirmed_transactions(N.confirmed_transactions, N.corrupt_transactions)
		N.all_unconfirmed_transactions = load_all_unconfirmed_transactions(N.confirmed_transactions, N.corrupt_transactions)
		
		"""
		CLI commands are parsed and respective functions are called.
		"""

		print(len(N.unconfirmed_transactions))
		
		if args=="update_UTXO":
			N.update_UTXO()
		elif args=="mine":
			N.mine()
		elif args=="validate":
			N.validate_pending_chains()
		elif args=="rl":
			node.request(N.valid_chain, "longest")
		elif args=="ra":
			node.request(N.valid_chain, "all")
		elif args=="send state":
			node.send_states()
		elif args=="print":
			N.print_chain()
		elif args=="help":
			commands()
		elif args=="showAccounts":
			N.showAccounts()
		elif args=="exit":
			node.disconnect()
			break
