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

temp_aes_key = "\xcaG\xd0J\x87O\xd8\xf7.\x95\xdd\xb7\xf3\x02\xef\xcf@\t\xa7/Q\xe6\x903$\xea\x90H\x1d\xd3\x1f\xd1"


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
    pkt = ''.join(list_pkt)
    # someone needs to send counter
    return pkt


class Bank(object):
    GOOD = "O"
    BAD = "N"
    ERROR = "E"

    def __init__(self, port, baud=115200, db_path="bank.json"):
        super(Bank, self).__init__()
        self.db = db.DB(db_path=db_path)
        self.atm = serial.Serial(port, baudrate=baud, timeout=10)

    def start(self):
        while True:
            command = self.atm.read()
            if command == 'w':
                log("Withdrawing")
                pkt = read_pkt()
                # someone needs to send counter
                ctr = os.urandom(16)
                obj2 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
                dec_pkt = obj2.decrypt(pkt)
                atm_id, card_id, amount = struct.unpack(">32s128sI", pkt)
                self.withdraw(atm_id, card_id, amount)
            elif command == 'b':
                log("Checking balance")
                pkt = read_pkt()
                # someone needs to send counter
                ctr = os.urandom(16)
                obj3 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
                dec_pkt = obj3.decrypt(pkt)
                atm_id, card_id = struct.unpack(">32s128s", pkt)
                self.check_balance(atm_id, card_id)
            elif command == "c":
                log("Changing pin")
                pkt = read_pkt()
                # someone needs to send counter
                ctr = os.urandom(16)
                obj4 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
                dec_pkt = obj4.decrypt(pkt)
                atm_id, card_id, old_pin, new_pin = struct.unpack(">32s128s8s8s", pkt)
                self.change_pin(atm_id, card_id, old_pin, new_pin)
            elif command != '':
                self.atm.write(self.ERROR)

    def withdraw(self, atm_id, card_id, amount):
        print "Withdraw attempt: " + card_id
        try:
            amount = int(amount)
            atm_id = str(atm_id)
            card_id = str(card_id)
        except ValueError:
            self.atm.write(self.ERROR)
            log("Bad value sent")
            return

        atm = self.db.get_atm(atm_id)
        if atm is None:
            self.atm.write(self.ERROR)
            log("Bad ATM ID")
            return

        num_bills = self.db.get_atm_num_bills(atm_id)
        if num_bills is None:
            self.atm.write(self.ERROR)
            log("Bad ATM ID")
            return

        if num_bills < amount:
            self.atm.write(self.BAD)
            log("Insufficient funds in ATM")
            return

        balance = self.db.get_balance(card_id)
        if balance is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
            return

        final_amount = balance - amount
        if final_amount >= 0:
            self.db.set_balance(card_id, final_amount)
            self.db.set_atm_num_bills(atm_id, num_bills - amount)
            log("Valid withdrawal")
            pkt = struct.pack(">32s128sI", atm_id, card_id, amount)
            ctr1 = os.urandom(16)
            obj5 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr1)
            enc_pkt = obj5.encrypt(pkt) + "EOP"
            self.atm.write(self.GOOD)
            self.atm.write(enc_pkt)
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
        if balance is None:
            self.atm.write(self.BAD)
            log("Bad card ID")
        else:
            log("Valid balance check")
            pkt = struct.pack(">32s128sI", atm_id, card_id, balance)
            ctr2 = os.urandom(16)
            obj6 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
            enc_pkt = obj6.encrypt(pkt) + "EOP"
            self.atm.write(self.GOOD)
            self.atm.write(pkt)

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
            self.db.admin_set_pin(card_id, new_pin)
            log("Pin changed")
            pkt = struct.pack(">32s128s", atm_id, card_id)
            ctr3 = os.urandom(16)
            obj7 = AES.new(temp_aes_key, AES.MODE_CTR, counter=ctr)
            enc_pkt = obj7.encrypt(pkt)
            self.atm.write(self.GOOD) + "EOP"
            self.atm.write(pkt)



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
