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
		#darab
		# Treat coinbase specially: no inputs, just add outputs to pending UTXO
		try:
			# idempotent behavior: if already processed, do not mutate state again
			if Tx.get('id') in self.valid_but_unconfirmed_transactions:
				return True
			if Tx.get('id') in self.corrupt_transactions:
				return False
			if Tx.get('COINBASE', False):
				# coinbase must have no inputs
				if len(Tx.get('inputs', [])) != 0:
					self.corrupt_transactions[Tx['id']] = Tx
					return False
				# add outputs
				for out_index, output in enumerate(Tx.get('outputs', [])):
					value, pubkey_hash = output
					self.UTXO_Database_Pending[(Tx['id'], out_index)] = (value, pubkey_hash)
				# track seen pubkeys for balances
				if not hasattr(self, 'all_pubkey_hashes'):
					self.all_pubkey_hashes = set()
				for _, pubkey_hash in Tx.get('outputs', []):
					self.all_pubkey_hashes.add(pubkey_hash)
				self.valid_but_unconfirmed_transactions[Tx['id']] = Tx
				return True

			# For non-coinbase, verify signature integrity and UTXO validity using a temp copy
			temp_utxo = copy.deepcopy(self.UTXO_Database_Pending)

			# signature and ownership checks for each input
			current_hash = calculateHash(stringifyTransactionExcludeSig(Tx))
			for inp in Tx.get('inputs', []):
				parent_txn_id, output_number, signature, pub_key = inp
				final_string = str(parent_txn_id) + ':' + str(current_hash)
				# verify signature
				if not VerifySignature(final_string, signature, pub_key):
					self.corrupt_transactions[Tx['id']] = Tx
					return False
				# verify referenced UTXO exists and belongs to given pubkey
				parent_key = (parent_txn_id, output_number)
				if parent_key not in temp_utxo:
					self.corrupt_transactions[Tx['id']] = Tx
					return False
				value, expected_pubkey_hash = temp_utxo[parent_key]
				if expected_pubkey_hash != hashPubKey(pub_key):
					self.corrupt_transactions[Tx['id']] = Tx
					return False

			# compute input and output sums, and spend inputs from temp_utxo
			inputs_total = 0
			for inp in Tx.get('inputs', []):
				parent_txn_id, output_number, _, _ = inp
				key = (parent_txn_id, output_number)
				if key not in temp_utxo:
					self.corrupt_transactions[Tx['id']] = Tx
					return False
				val, _ = temp_utxo[key]
				inputs_total += val
				# spend it
				del temp_utxo[key]

			outputs_total = 0
			for out_index, output in enumerate(Tx.get('outputs', [])):
				value, pubkey_hash = output
				outputs_total += value

			if inputs_total < outputs_total:
				self.corrupt_transactions[Tx['id']] = Tx
				return False

			# add outputs to temp_utxo, then commit to pending
			for out_index, output in enumerate(Tx.get('outputs', [])):
				value, pubkey_hash = output
				temp_utxo[(Tx['id'], out_index)] = (value, pubkey_hash)

			self.UTXO_Database_Pending = temp_utxo

			# track seen pubkeys for balances
			if not hasattr(self, 'all_pubkey_hashes'):
				self.all_pubkey_hashes = set()
			for inp in Tx.get('inputs', []):
				_, _, _, pub_key = inp
				self.all_pubkey_hashes.add(hashPubKey(pub_key))
			for _, pubkey_hash in Tx.get('outputs', []):
				self.all_pubkey_hashes.add(pubkey_hash)

			self.valid_but_unconfirmed_transactions[Tx['id']] = Tx
			return True
		except Exception:
			# conservative: mark corrupt if any unexpected condition
			self.corrupt_transactions[Tx.get('id', f"bad_{time.time()}")] = Tx
			return False
			#darab

	def findValidButUnconfirmedTransactions(self):
		# find 5 valid transactions that are NOT in a block yet
		#darab
		valid = []
		for tx in self.unconfirmed_transactions:
			if len(valid) >= 5:
				break
			if tx['id'] in self.valid_but_unconfirmed_transactions or tx['id'] in self.corrupt_transactions:
				continue
			if self.verifyTransaction(tx):
				valid.append(tx)
		return valid
		#darab

	## PART TWO - Mining and Proof-Of-Work ##
	# Mine Blocks -- skip genesis block
	def mine(self):

		# Save block to physical memory here. 
		# Syntax to store block: save_object(new_block,"valid_chain/block{}.block".format(new_block.index))
		# save_object(NewBlock,"valid_chain/block{}.block".format(NewBlock.index))
		self.update_UTXO()
		valid_txs = self.findValidButUnconfirmedTransactions()
		if not valid_txs:
			return
		last_blk = self.last_block()
		index = last_blk.index + 1
		previous_hash = self.computeBlockHash(last_blk)
		time_stamp = datetime.datetime.now().strftime("%d-%m-%Y (%H:%M:%S)")
		new_block = Block(index, valid_txs, time_stamp, previous_hash, self.STUDENT_ID, nonce=0)
		self.proof_of_work(new_block)
		self.valid_chain.append(new_block)
		save_object(new_block, "valid_chain/block{}.block".format(new_block.index))
		# Optionally, update pending UTXO by applying included txs
		for tx in valid_txs:
			# remove spent inputs
			if not tx.get('COINBASE', False):
				for inp in tx.get('inputs', []):
					parent_txn_id, output_number, _, _ = inp
					key = (parent_txn_id, output_number)
					if key in self.UTXO_Database_Pending:
						del self.UTXO_Database_Pending[key]
			# add outputs
			for out_index, output in enumerate(tx.get('outputs', [])):
				value, pubkey_hash = output
				self.UTXO_Database_Pending[(tx['id'], out_index)] = (value, pubkey_hash)


	def proof_of_work(self, block):
		"""
		This method performs proof of work on the given block.
		Iterates a nonce value,
		which gives a block hash that satisfies PoW dificulty condition.
		"""
		prefix = '0' * self.DIFFICULTY
		#darab
		# start from current nonce
		while True:
			block_hash = self.computeBlockHash(block)
			if block_hash.startswith(prefix):
				return block.nonce
			block.nonce += 1
		#darab



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
		#darab
		# Basic structural checks
		if not temp_chain:
			return False

		# Check previous hash linkage and difficulty
		prev_hash = last_block_hash
		for i, blk in enumerate(temp_chain):
			# previous hash linkage
			if blk.previous_hash != prev_hash:
				return False
			# difficulty
			if not self.computeBlockHash(blk).startswith('0' * self.DIFFICULTY):
				return False
			prev_hash = self.computeBlockHash(blk)

		# Check indexes are strictly increasing and contiguous with current_longest overlap
		for i in range(1, len(temp_chain)):
			if temp_chain[i].index != temp_chain[i-1].index + 1:
				return False

		# Transaction-level checks using a temporary UTXO starting from current valid UTXO
		# Build UTXO from our current valid chain
		self.update_UTXO()
		temp_utxo = copy.deepcopy(self.UTXO_Database)
		seen_tx_ids = set()

		for blk in temp_chain:
			# allow blocks with fewer than 5 transactions
			for tx in blk.transactions:
				# duplicate tx ids within pending chain
				if tx['id'] in seen_tx_ids:
					return False
				seen_tx_ids.add(tx['id'])

				# validate transaction against temp_utxo without mutating node state
				if tx.get('COINBASE', False):
					for out_index, output in enumerate(tx.get('outputs', [])):
						value, pubkey_hash = output
						temp_utxo[(tx['id'], out_index)] = (value, pubkey_hash)
					continue

					# non-coinbase
				current_hash = calculateHash(stringifyTransactionExcludeSig(tx))
				# verify every input
				inputs_total = 0
				to_spend_keys = []
				for inp in tx.get('inputs', []):
					parent_txn_id, output_number, signature, pub_key = inp
					final_string = str(parent_txn_id) + ':' + str(current_hash)
					if not VerifySignature(final_string, signature, pub_key):
						return False
					key = (parent_txn_id, output_number)
					if key not in temp_utxo:
						return False
					val, expected_pubkey_hash = temp_utxo[key]
					if expected_pubkey_hash != hashPubKey(pub_key):
						return False
					inputs_total += val
					to_spend_keys.append(key)

				outputs_total = 0
				for out_index, output in enumerate(tx.get('outputs', [])):
					value, pubkey_hash = output
					outputs_total += value

				if inputs_total < outputs_total:
					return False

				# spend inputs and add outputs
				for key in to_spend_keys:
					if key not in temp_utxo:
						return False
					del temp_utxo[key]
				for out_index, output in enumerate(tx.get('outputs', [])):
					value, pubkey_hash = output
					temp_utxo[(tx['id'], out_index)] = (value, pubkey_hash)

		return True
		#darab

	def showAccounts(self):
		#return a dictionary with mapping from pubkeyHash to total crypto available		
		#Uses the PENDING UTXO database
		#darab
		balances = {}
		for (_, _), (value, pubkey_hash) in self.UTXO_Database_Pending.items():
			balances[pubkey_hash] = balances.get(pubkey_hash, 0) + value

		# Ensure zero entries for seen users
		seen = set()
		if hasattr(self, 'all_pubkey_hashes'):
			seen |= set(self.all_pubkey_hashes)
		for tx in self.valid_but_unconfirmed_transactions.values():
			for _, pubkey_hash in tx.get('outputs', []):
				seen.add(pubkey_hash)
			for inp in tx.get('inputs', []):
				_, _, _, pub_key = inp
				seen.add(hashPubKey(pub_key))
		for pk in seen:
			if pk not in balances:
				balances[pk] = 0
		return balances
		#darab
	def update_UTXO(self):
		#darab
		# rebuild UTXO from valid_chain (ignore genesis block)
		self.UTXO_Database = {}
		chain = sorted(self.valid_chain, key=self.sortHelper)
		for block in chain:
			if block.index == 0:
				continue
			for tx in block.transactions:
				if tx.get('COINBASE', False):
					for out_index, output in enumerate(tx.get('outputs', [])):
						value, pubkey_hash = output
						self.UTXO_Database[(tx['id'], out_index)] = (value, pubkey_hash)
					continue

				# spend inputs
				for inp in tx.get('inputs', []):
					parent_txn_id, output_number, _, _ = inp
					key = (parent_txn_id, output_number)
					if key in self.UTXO_Database:
						del self.UTXO_Database[key]
				# add outputs
				for out_index, output in enumerate(tx.get('outputs', [])):
					value, pubkey_hash = output
					self.UTXO_Database[(tx['id'], out_index)] = (value, pubkey_hash)
					#darab


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
