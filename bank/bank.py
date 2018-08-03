""" Bank Server
This module implements a bank server interface
"""

import uuid
import db
import logging
from logging import info as log
import sys
import serial
import argparse
import struct
from Crypto.Cipher import AES
import os
from os import urandom
from Crypto.Hash import SHA256


def read_pkt():
    """Reads a packet of undefined length from serial"""
    # since encrypted packet is undefined length, read from serial until EOP
    pkt = ""
    while pkt[-1:-4] != "EOP":
        pkt = pkt + self.atm.read()
    list_pkt = list(pkt)
    # remove "EOP" signifier from the packet so it's the right length to decrypt and unpack
    list_pkt.pop(-1)
    list_pkt.pop(-1)
    list_pkt.pop(-1)
    atm_id = ""
    i=0
    while i<128:
        atm_id = atm_id + list_pkt.pop(0)
        i++

    pkt = ''.join(list_pkt)
    # someone needs to send counter
    return atm_id, pkt

#Check if the pin matches the pin in the database
def check_pin(card_id, pin):
    if pin != admin_get_pin(card_id):
        return False
    else:
        return True

#Check if the tamper code matches the tamper code in the database
def check_tamper(card_id, tamper_hash):
    if pin != admin_get_tamper(card_id):
        return False
    else:
        return True

#make aes variable for encrypting the card stuff(we can put "card_aes" instead of "AES.new(card_aes_key, AES.MODE_CTR, counter=card_ctr)" )
def setup_card_aes(card_id):
    card_ctr = admin_get_card_iv(card_id)
    card_aes_key = admin_get_card_key(card_id)
    card_aes = AES.new(card_aes_key, AES.MODE_CTR, counter=lambda:card_ctr)
    return card_aes

#make aes variable for encrypting the atm stuff (we can put "atm_aes" instead of "AES.new(atm_aes_key, AES.MODE_CTR, counter=atm_ctr)" )
def setup_atm_aes(atm_id):
    atm_ctr = admin_get_atm_iv(atm_id)
    atm_aes_key = admin_get_atm_key(atm_id)
    atm_aes = AES.new(atm_aes_key, AES.MODE_CTR, counter=lambda:atm_ctr)
    return atm_aes

def generate_new(card_id, atm_id):
    uuid = urandom(128).encode("hex")
    tamper_code = urandom(128).encode("hex")
    card_aes_key = urandom(32).encode("hex")
    card_aes_ctr = urandom(16).encode("hex")
    atm_aes_key = urandom(32).encode("hex")
    atm_aes_ctr = urandom(16).encode("hex")

    return tamper_code, card_aes_key, card_aes_ctr, atm_aes_key, atm_aes_ctr


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)

    '''This functions derypts and unpacks the packets based on command (because the command dictates the packet structure),

    then checks if the pin and tamper code are correct(by calling check_pin and check_tamper),

    if it is correct it calls the functions function the corresponds to the command(ex. "w" - self.withdraw()),

    if not it prints an error message based on
    what was not correct ("Bad Pin for incorrect pin, and "Bad Card" for incorrect tamper code)
    '''
    def start(self):
        while True:
            command = self.atm.read()
            if command == 'w':
                # "w" means withdraw
                log("Withdrawing")
                #Decrypting
                atm_id, pkt = read_pkt()
                atm_aes = setup_atm_aes(atm_id)
                dec_pkt = atm_aes.decrypt(pkt)
                #Unpacking
                card_pkt_len = len(dec_pkt)-160
                buffer, pin, amount, card_id, card_pkt = struct.unpack(">8s8s16s128s%ds", % card_pkt_len, atm_pkt)
                card_aes = setup_card_aes(card_id)
                tamper_hash = card_aes.decrypt(card_pkt)
                #Checking if Pin and tamper code are correct
                if check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) == True:
                    #Calling the Withdraw function because everything is correct :)
                    new_bal = self.withdraw(atm_id, card_id, amount)
                    new_tamp, new_card_key, new_card_ctr, new_atm_key, new_atm_ctr = generate_new(card_id, atm_id)
                    bal_aes_key = SHA256.new(pin + SHA256.new(new_tamp).hexdigest()).hexdigest()
                    bal_aes = AES.new(bal_aes_key, AES.MODE_CTR, ctr=lambda:new_card_ctr)
                    bal_enc = bal_aes.encrypt(new_bal)
                    admin_set_balance(card_id, bal_enc)
                    admin_set_tamper(card_id, SHA256.new(new_tamp).hexdigest())
                    admin_set_card_key(card_id, new_card_key)
                    admin_set_card_iv(card_id, new_card_ctr)
                    admin_set_atm_key(atm_id, new_atm_key)
                    admin_set_atm_iv(atm_id, new_atm_ctr)
                elif check_pin(card_id, pin) != True && check_tamper(card_id, tamper_hash) == True:
                    #logging "bad pin" because the pin was incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN")
                    return
                elif check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) != True:
                    #Logging "Bad Card" because the tamper code is incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad card")
                    return
                else:
                    #logging "Bad PIN and card" because both are incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN and card")
                    return
            elif command == 'b':
                #b means check balance
                log("Checking balance")
                #Decrypting
                atm_id, pkt = read_pkt()
                atm_aes = setup_atm_aes(atm_id)
                dec_pkt = atm_aes.decrypt(pkt)
                #Unpacking
                card_pkt_len = len(dec_pkt)-144
                buffer, pin, card_id, card_pkt = struct.unpack(">8s8s128s%ds", % card_pkt_len, atm_pkt)
                card_aes = setup_card_aes(card_id)
                tamper_hash = card_aes.decrypt(card_pkt)
                #Checking if Pin and tamper code are correct
                if check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) == True:
                    #Calling the Check Balance function because everything is correct :)
                    bal = self.check_balance(atm_id, card_id)
                    new_tamp, new_card_key, new_card_ctr, new_atm_key, new_atm_ctr = generate_new(card_id, atm_id)
                    admin_set_tamper(card_id, SHA256.new(new_tamp).hexdigest())
                    admin_set_card_key(card_id, new_card_key)
                    admin_set_card_iv(card_id, new_card_ctr)
                    admin_set_atm_key(atm_id, new_atm_key)
                    admin_set_atm_iv(atm_id, new_atm_ctr)
                elif check_pin(card_id, pin) != True && check_tamper(card_id, tamper_hash) == True:
                    #logging "bad pin" because the pin was incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN")
                    return
                elif check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) != True:
                    #Logging "Bad Card" because the tamper code is incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad card")
                    return
                else:
                    #logging "Bad PIN and card" because both are incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN and card")
                    return
            elif command == "c":
                #c means changing pin
                log("Changing pin")
                #Decrypting
                atm_id, pkt = read_pkt()
                atm_aes = setup_atm_aes(atm_id)
                dec_pkt = atm_aes.decrypt(pkt)
                #Unpacking
                card_pkt_len = len(dec_pkt)-144
                old_pin, new_pin, card_id, card_pkt = struct.unpack(">8s8s128s%ds", % card_pkt_len, atm_pkt)
                card_aes = setup_card_aes(card_id)
                tamper_hash = card_aes.decrypt(card_pkt)
                #Checking if Pin and tamper code are correct
                if check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) == True:
                    #Calling the Check Balance function because everything is correct :)
                    new_tamp, new_card_key, new_card_ctr, new_atm_key, new_atm_ctr = generate_new(card_id, atm_id)
                    admin_set_tamper(card_id, SHA256.new(new_tamp).hexdigest())
                    admin_set_card_key(card_id, new_card_key)
                    admin_set_card_iv(card_id, new_card_ctr)
                    admin_set_atm_key(atm_id, new_atm_key)
                    admin_set_atm_iv(atm_id, new_atm_ctr)
                    bal = self.change_pin(atm_id, card_id, old_pin, new_pin)
                elif check_pin(card_id, pin) != True && check_tamper(card_id, tamper_hash) == True:
                    #logging "bad pin" because the pin was incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN")
                    return
                elif check_pin(card_id, pin) == True && check_tamper(card_id, tamper_hash) != True:
                    #Logging "Bad Card" because the tamper code is incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad card")
                    return
                else:
                    #logging "Bad PIN and card" because both are incorrect :(
                    self.atm.write(self.BAD)
                    log("Bad PIN and card")
                    return
                ###
                pkt = read_pkt()
                ctr = os.urandom(16)
                #decrypting
                obj4 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
                dec_pkt = obj4.decrypt(pkt)
                #Unpacking
                atm_id, card_id, old_pin, new_pin = struct.unpack(">32s128s8s8s", pkt)
                self.change_pin(atm_id, card_id, old_pin, new_pin)
            elif command != '':
                self.atm.write(self.ERROR)
''' This is the withdraw function, first it assigns the values from the packet into local variables
and checks if the values are the correct type,

second it checks the atm id by calling the get_atm function (defined in db.py),

third it checks if that the database has the number of bills in that atm using the get_atm_num_bills
function(defined in db.py),

fourth it checks if the atm has enough bills for the transaction,

fifth it checks if there is a balance associated with the card in the database,

Sixth it checks if the balance is greater than the withdrawl amount(so no one can with draw more than
they have)

if this is all correct, it withdraws the money, updates the balance in the database, updates the bill count
in the database, logs "Valid Withdrawl", packs and encrypts a package with the card id , atm id, and withdraw amount
and sends it to the atm

'''
    def withdraw(self, atm_id, card_id, amount):
        print "Withdraw attempt: " + card_id
        try:
        #assigns variables
            amount = int(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
        #If it can't sends a value error
        except ValueError:
            self.atm.write(self.ERROR)
            log("Bad value sent")
            return

        #Check if ATM id is valid
        atm = self.db.get_atm(atm_id)
        if atm is None:
            self.atm.write(self.ERROR)
            log("Bad ATM ID")
            return

        #Check if that ATM has an amount of bills associated with it
        num_bills = self.db.get_atm_num_bills(atm_id)
        if num_bills is None:
            self.atm.write(self.ERROR)
            log("Bad ATM ID")
            return

        #Checks if the ATM has enough bills for the transaction
        if num_bills < amount:
            self.atm.write(self.BAD)
            log("Insufficient funds in ATM")
            return

        #Checks if there is a balance associated with the card
        balance = self.db.get_balance(card_id)
        old_bal_key = SHA256.new(pin + tamper_hash).hexdigest()
        bal_ctr = admin_get_card_iv(card_id)
        bal_aes = AES.new(old_bal_key, AES.MODE_CTR, ctr=lambda:bal_ctr)
        bal = bal_aes.decrypt(balance)

        if bal is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
            return
        #Checks if amount is less than balance
        final_amount = bal - amount
        if final_amount >= 0:
            self.db.set_balance(card_id, final_amount)
            self.db.set_atm_num_bills(atm_id, num_bills - amount)
            log("Valid withdrawal")
            pkt_for_card = card_aes.encrypt(struct.pack("32s16s128s", new_card_key, new_card_ctr, new_tamp))
            pkt_for_atm = atm_aes.encrypt(struct.pack("32s16s16s%ds", % len(pkt_for_card), new_atm_key, new_atm_ctr, final_amount, pkt_for_card))
            self.atm.write(self.GOOD)
            self.atm.write(pkt_for_atm) + "EOP"
            return final_amount
        else:
            self.atm.write(self.BAD)
            log("Insufficient funds in account")

    def check_balance(self, atm_id, card_id):
        print "Balance check: " + card_id
        if self.db.get_atm(atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return

        balance = self.db.get_balance(str(card_id))
        bal_aes_key = SHA256.new(pin + tamper_hash).hexdigest()
        bal_ctr = admin_get_card_iv(card_id)
        bal_aes = AES.new(bal_aes_key, AES.MODE_CTR, ctr=lambda:bal_ctr)
        bal = bal_aes.decrypt(balance)

        if bal is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
        else:
            log("Valid balance check")
            pkt_for_card = card_aes.encrypt(struct.pack("32s16s128s", new_card_key, new_card_ctr, new_tamp))
            pkt_for_atm = atm_aes.encrypt(struct.pack("32s16s16s%ds", % len(pkt_for_card), new_atm_key, new_atm_ctr, bal, pkt_for_card))
            self.atm.write(self.GOOD)
            self.atm.write(pkt_for_atm) + "EOP"
            return bal

    def change_pin(self, atm_id, card_id, old_pin, new_pin):
        """Updates the pin in the bank's database, provided that the old pin is correct

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            old_pin (str): current 8-digit pin associated with account
            new_pin (str): user-entered 8-digit pin to replace old_pin
        """
        if self.db.admin_get_pin(card_id) != old_pin:
            self.atm.write(self.BAD)
            log("Invalid pin")
            return
        if self.db.get_atm(atm_id) is None:
            self.atm.write(self.BAD)
            log("Invalid ATM ID")
            return
        else:
            hash_pin = SHA256.new(new_pin).hexdigest()
            self.db.admin_set_pin(card_id, hash_pin)
            log("Pin changed")
            pkt_for_card = card_aes.encrypt(struct.pack("32s16s128s", new_card_key, new_card_ctr, new_tamp))
            pkt_for_atm = atm_aes.encrypt(struct.pack("32s16s%ds", % len(pkt_for_card), new_atm_key, new_atm_ctr, pkt_for_card))
            self.atm.write(self.GOOD)
            self.atm.write(pkt_for_atm) + "EOP"
            return



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", help="Serial port ATM is connected to")
    parser.add_argument("--baudrate", default=115200, help="Optional baudrate (default 115200)")
    return parser.parse_args()


def main():
    log = logging.getLogger('')
    log.setLevel(logging.DEBUG)
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(log_format)
    log.addHandler(ch)

    args = parse_args()

    bank = Bank(args.port, args.baudrate)
    try:
        print "Starting up bank..."
        bank.start()
    except KeyboardInterrupt:
        print "Shutting down bank..."


if __name__ == "__main__":
    main()
