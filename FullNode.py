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
"""
Establishing connection with backend
"""
class FullNode:
	def __init__(self, id):
		"""
		DO NOT EDIT
		"""
		self.DIFFICULTY = 5	# Difficulty setting 
		self.STUDENT_ID = id # Do not edit, this is your student ID
		self.unconfirmed_transactions = []   # Raw 5 TXNs that you will get from the mempool 
		self.all_unconfirmed_transactions = [] # all Raw unconfirmed txns from mempool
		self.valid_but_unconfirmed_transactions = {}
		self.valid_chain, self.confirmed_transactions = load_valid_chain()  # Your valid chain, all the TXNs in that valid chain
		self.corrupt_transactions = {}  # Initialize known invalid TXNs. To be appended to (by you, later). These are transactions whose signatures don't match or their output > input
		self.UTXO_Database_Pending = {} # This is a temporary UTXO database you may use.  
		self.UTXO_Database = {}


	def last_block(self):
		"""
		DO NOT EDIT
		returns last block of the valid chain loaded in memory
		"""
		self.valid_chain.sort(key = self.sortHelper)
		return self.valid_chain[-1]


	

	
	## PART ONE - UTXO Database Construction##

	## Add code for part 1 here (You can make as many helper function you want)
	def verifyTransaction(self, Tx):
		pass

	def findValidButUnconfirmedTransactions(self):
		# find 5 valid transactions that are NOT in a block yet
		pass

	## PART TWO - Mining and Proof-Of-Work ##
	# Mine Blocks -- skip genesis block
	def mine(self):

		# Save block to physical memory here. 
		# Syntax to store block: save_object(new_block,"valid_chain/block{}.block".format(new_block.index))
		# save_object(NewBlock,"valid_chain/block{}.block".format(NewBlock.index))
		pass



	def proof_of_work(self, block):
		"""
		This method performs proof of work on the given block.
		Iterates a nonce value,
		which gives a block hash that satisfies PoW dificulty condition.
		"""
		pass



	def verify_chain(self,current_longest,temp_chain,last_block_hash):
		#current_longest is the longest chain including any overlap with your valid chain
		#temp_chain is only the difference between your valid chain and the current longest chain
		#last_block_hash is the hash of the previous block of temp_chain[0]. If there is no overlap, for example, this should be
		#the hash of the genesis block
		"""
		This method performs the following validity checks on the input temp, or pending, chain.
			- whether length of temp_chain is greater than current valid chain (consider checking indexes)
			- whether previous hashes of blocks correspond to calculated block hashes of previous blocks
			- whether the difficulty setting has been achieved
			- whether each transaction is valid
				- no two or more transactions have same id
				- the signature in transaction is valid
				- The UTXO calculation is correct (input >= sum of outputs)
				- The UTXO is not being double spent
		Return True if all is good
		Return False if failed any one of the checks
		
		temp_chain: your peer's blocks/chain that is being tested
		current_longest: your valid chain + temp_chain/new blocks your peer mined
		last_block_hash: the hash of your last block 
		
		"""
		return False
	
	def showAccounts(self):
		#return a dictionary with mapping from pubkeyHash to total crypto available		
		#Uses the PENDING UTXO database
		return
	
	def update_UTXO(self):
		return


	## Donot edit anything below

	def validate_pending_chains(self):
		"""
		DO NOT EDIT
		This method loads pending chains from the 'pending_chains' folder.
		It then calls verify_chain method on each chain performing a series of validity checks
		if all the tests pass, it replaces the current valid chain with pending chain and saves it in valid chain folder. 
		"""
		self.valid_chain, self.confirmed_transactions = load_valid_chain()
		MAIN_DIR = "pending_chains"
		subdirectories = [name for name in os.listdir(MAIN_DIR) if os.path.isdir(os.path.join(MAIN_DIR, name))]
		for directory in subdirectories:
			temp_chain = []
			DIR = MAIN_DIR + "/" + directory 
			block_indexes = [name for name in os.listdir(DIR) if os.path.isfile(os.path.join(DIR, name))]
			block_indexes.sort()
			for block_index in block_indexes:
				try:
					with open(DIR+'/{}'.format(block_index), 'rb') as inp:
						block = pickle.load(inp)
						temp_chain.append(block)
				except:
					pass
			
			temp_chain.sort(key=self.sortHelper)
			last_block_index=temp_chain[0].index-1
			if last_block_index >= len(self.valid_chain):
				continue

			last_block_hash=self.computeBlockHash(self.valid_chain[last_block_index])
			current_longest=self.valid_chain[:last_block_index+1]+temp_chain
			if (self.verify_chain(current_longest, temp_chain, last_block_hash)):
				print("Replaced valid chain with chain from", directory)
				self.valid_chain = current_longest
				save_chain(current_longest)
				self.valid_chain, self.confirmed_transactions = load_valid_chain()
			else:
				print("Rejected chain from", directory)
			pc_del_command="rm -rf "+DIR
			os.system(pc_del_command)


	def computeBlockHash(self,block): #Compute the aggregate transaction hash.
		block_string = json.dumps(block.__dict__, sort_keys=True)
		return sha256(block_string.encode()).hexdigest()

	def sortHelper(self, block):
		return block.index

	def sortHelperNumber(self, tx):
		return tx['number']

	def print_chain(self):
		"""
		DO NOT EDIT
		Prints the current valid chain in the terminal.
		"""
		self.valid_chain, self.confirmed_transactions = load_valid_chain()

		self.valid_chain.sort(key=self.sortHelper)

		for block in self.valid_chain:
			print ("***************************")
			print(f"Block index # {block.index}")

			for trans in block.transactions:
				if block.index:
					print(f'Transaction number {trans["number"]} with hash {trans["id"]}')
				
			print("---------------------------")
			
			print("nonce: {}".format(block.nonce) )
			print("previous_hash: {}".format(block.previous_hash) )
			print('hash: {}'.format(self.computeBlockHash(block)))
			print('Miner: {}'.format(block.miner))
			print ("***************************")
			print("")
