import socket 
import threading
import sys
import json
import pickle5 as pickle
import os
from Block import Block
from Transaction import Transaction
from util import*
from hashlib import sha256
import time
END_MSG='#END#'
# DO NOT EDIT
class Node:
	def __init__(self, host, port,backend_addr, ID):
		self.port=port 
		self.host=host
		self.Network=[socket]
		self.enable=True
		self.backend_addr= backend_addr
		self.soc=socket.socket()
		self.state_sender=socket.socket()
		self.connected=False
		self.userID = ID
		self.PACKET_SIZE = 4096
		self.msg_count=0
		threading.Thread(target = self.listen).start()

	def start_connection(self):
		"""
		Starts connection with backend
		"""
		if not self.connected:
			self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.soc.bind(("localhost", self.port))
			self.soc.connect(self.backend_addr)
			self.state_sender.connect((self.backend_addr[0], self.backend_addr[1]+1))
			self.connected=True
			print("Connected to backend")

	def find_end(self,message):
		for idx in range(0,len(message)-len(END_MSG)):
			if message[idx:len(END_MSG)+idx]==END_MSG:
				return True
		return False
	def listen(self):
		"""
		This method listens to messages from backend.
		"""
		while self.enable:
			try:
				message= None
				message = self.soc.recv(self.PACKET_SIZE).decode("utf-8")
				if message != None:
					while True:
						try:
							self.soc.settimeout(2.0)
							data = self.soc.recv(self.PACKET_SIZE).decode("utf-8")
							message+=data
							if self.find_end(message):
								message=message.split(END_MSG)[0]
								state_sender.settimeout(None)
								break
						except:
							self.soc.settimeout(None)
							break
				if message!= None:
					self.handleTransmission(message)
			except:
				pass


	def handleTransmission(self,message):
		"""
		This method reacts to the messages from backend
		"""
		delimiter='|'
		type,sender,data=message.split(delimiter)
		if type=='pending_chain':
			chain=self.json_to_chain(data)
			self.save_pending_chain(chain, sender)
		elif type == 'timeout':
			print("User timed out.")
			self.connected = False
			self.soc.close()
			self.state_sender.close()
			self.soc = socket.socket()
			self.state_sender = socket.socket()
	def mux_msg(self,message):
		message+=END_MSG
		message_list=[]
		for idx in range(0,len(message),self.PACKET_SIZE):
			msg=message[idx:self.PACKET_SIZE+idx]
			if len(msg)!=self.PACKET_SIZE:
				msg=msg+'X'*(self.PACKET_SIZE-len(msg))
			message_list.append(msg)
		return message_list

	def send_states(self):
		"""
		This method on end sends the current state of a node's Blockchain to the backend.
		Sends only if there's a change in the chain.
		"""
		hash_headers_new= None
		current_chain,_ = load_valid_chain()
		hash_headers=[self.compute_hash(block) for block in current_chain]	
		if hash_headers_new!=hash_headers:
			self.start_connection()
			delimiter='|'
			type='state'
			packet=type+delimiter+self.userID+delimiter+self.chain_to_json(current_chain)+delimiter+' '.join(hash_headers)
			packets = self.mux_msg(str(packet))
			for p in packets:
				self.state_sender.send(p.encode('utf-8'))
			hash_headers_new=hash_headers
			print("State sent")

	def json_to_chain(self,js):
		"""
		Converts json chain to a list chain
		"""
		chain_json=json.loads(js)
		chain=[]
		for key in chain_json:
			block=chain_json[key]
			block_new=Block(block['index'],block['transactions'],block['time_stamp'],block['previous_hash'],block['miner'],block['nonce'])
			chain.append(block_new)
		return chain
		
	def save_pending_chain(self, chain, senderID): 
		"""
		Saves a recieved pending chain from backed to the pending chain folder
		"""
		block_count=chain[0].index
		DIR='pending_chains'
		pending_chains=os.listdir(DIR)
		
		userdir=DIR+'/{}'.format(senderID)
		os.system('rm -rf {}'.format(userdir))
		os.mkdir(DIR+'/{}'.format(senderID))
		print("Chain received from", senderID)
		for block in chain:
			send_dir="{}/{}/block{}.block".format(DIR,senderID,block_count)
			save_object(block,send_dir)
			block_count+=1
	def chain_to_json(self,chain):
		"""
		Converts a list chain to a json chain
		"""
		chain_json={}
		for block in chain:
			chain_json[str(block.index)]=block.__dict__
		chain_json=json.dumps(chain_json)
		return chain_json

	def broadcast(self,chain):
		"""
		This method sends the current chain to the backend to broadcast to all the nodes.
		"""
		chain_json=self.chain_to_json(chain)
		type='broadcast'
		delimiter='|'
		packet=type+delimiter+self.userID+delimiter+chain_json
		self.start_connection()
		packets = self.mux_msg(packet)
		for p in packets:
			self.soc.send(p.encode('utf-8'))

	def request(self, chain, requested):
		"""
		This method requests the longest or all the chains present in the network depending on 'requested' variable
		"""
		hash_headers=[self.compute_hash(block) for block in chain]
		delimiter='|'
		type='request_' + requested
		packet=type+delimiter+self.userID+delimiter+' '.join(hash_headers)
		self.start_connection()
		packets = self.mux_msg(packet)
		for p in packets:
			self.soc.send(p.encode('utf-8'))
		print("Chain(s) request sent")

	def compute_hash(self,block):
		"""	
		Computes the hash of the block by treating all the contents of the block object as a dict.
		"""
		block_string = json.dumps(block.__dict__, sort_keys=True)
		return sha256(block_string.encode()).hexdigest()
		
	def disconnect(self):
		self.soc.close()
		self.state_sender.close()
		os._exit(1)
