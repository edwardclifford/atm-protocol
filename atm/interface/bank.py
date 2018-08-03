"""Backend of ATM interface for xmlrpc"""

import logging
import struct
import serial
from Crypto.Cipher import AES
from Crypto import Random
from bank.bank import read_pkt


def generate_aes(self, aes_key):
    ctr = os.urandom(16)
    aesProg = AES.new(aes_key, AES.MODE_CTR, counter:lambda=ctr)

    return aesProg


temp_aes_key = "\xcaG\xd0J\x87O\xd8\xf7.\x95\xdd\xb7\xf3\x02\xef\xcf@\t\xa7/Q\xe6\x903$\xea\x90H\x1d\xd3\x1f\xd1"


class Bank:
    """Interface for communicating with the bank

    Args:
        port (serial.Serial): Port to connect to
    """

    def __init__(self, port, verbose=False):
        self.ser = serial.Serial(port, baudrate = 115200)
    self.verbose = verbose

    def _vp(self, msg, stream=logging.info):
        """Prints message if verbose was set

        Args:
            msg (str): message to print
            stream (logging function, optional): logging function to call
        """
        if self.verbose:
            stream("card: " + msg)

    def check_balance(self, atm_id, card_id):
        """Requests the balance of the account associated with the card_id

        Args:
            atm_id (str): UUID of the ATM
            card_id (str): UUID of the ATM card to look up

        Returns:
            str: Balance of account on success
            bool: False on failure
        """
        aes1 = generate_aes(temp_aes_key)
        pkt = struct.pack(">32s128s", atm_id, card_id)
        enc_pkt = "b" + aes1.encrypt(pkt) + "EOP"
        self.ser.write(enc_pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            return False

        pkt = read_pkt()
        dec_pkt = aes1.decrypt(pkt)
        aid, cid, bal = struct.unpack(">32s128sI", dec_pkt)
        self._vp('check_balance: returning balance')
        return bal

    def withdraw(self, atm_id, card_id, amount):
        """Requests a withdrawal from the account associated with the card_id

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            amount (str): Requested amount to withdraw

        Returns:
            str: hsm_id on success
            bool: False on failure
        """
        self._vp('withdraw: Sending request to Bank')
        aes2 = generate_aes(temp_aes_key)
        pkt = struct.pack(">32s128sI", atm_id, card_id, amount)
        enc_pkt = "w" + aes2.encrypt(pkt) + "EOP"
        self.ser.write(pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            self._vp('withdraw: request denied')
            return False

        pkt = read_pkt()
        dec_pkt = aes2.decrypt(pkt)
        aid, cid, amount = struct.unpack(">32s128sI", dec_pkt)
        self._vp('withdraw: Withdrawal accepted')
        return True
        
    def change_pin(self, atm_id, card_id, old_pin, new_pin):
        """Requests to change pin of account associated with

        Args:
            atm_id (str): UUID of the HSM
            card_id (str): UUID of the ATM card
            old_pin (str): current 8-digit pin associated with account
            new_pin (str): user-entered 8-digit pin to replace old_pin

        Returns:
            bool: True on success, False on failure
        """
        self._vp('Change pin: Sending request to Bank')
        aes3 = generate_aes(temp_aes_key)
        pkt = struct.pack(">32s128s8s8s", atm_id, card_id, old_pin, new_pin)
        enc_pkt = "c" + aes3.encrypt(pkt) + "EOP"
        self.ser.write(enc_pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            self._vp('change pin: request denied')
            return False

        pkt = read_pkt()
        dec_pkt = aes3.decrypt(pkt)
        aid, cid = struct.unpack(">32s128s", dec_pkt)
        self._vp('change pin: request accepted')
        return True

    def provision_update(self, uuid, pin, balance, tampercode, key, iv):
        pkt = struct.pack(">128s32s16s32s32s16s", uuid, pin, balance, tampercode, key, iv)
        self.ser.write("p" + pkt)
