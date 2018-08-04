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

    def check_balance(self, atm_id, card_id, pin, aes_key, aes_ctr, card_pkt):
        """Requests the balance of the account associated with the card_id

        Args:
            atm_id (str): UUID of the ATM
            card_id (str): UUID of the ATM card to look up

        Returns:
            str: Balance of account on success
            bool: False on failure
        """

        aes1 = AES.new(aes_key, AES.MODE_CTR, counter=lambda:aes_ctr)
        pkt = struct.pack(">8s8s128s%ds", % len(card_pkt), "00000000", pin, atm_id, card_pkt)
        enc_pkt = "b" + atm_id + aes1.encrypt(pkt) + "EOP"
        self.ser.write(enc_pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            return False

        pkt = read_pkt()
        dec_pkt = aes1.decrypt(pkt)
        len_card_pkt = len(dec_pkt)-64
        new_atm_key, new_atm_iv, bal, pkt_for_card = struct.unpack(">32s128s16s%ds" % len_card_pkt, dec_pkt)
        self._vp('check_balance: returning balance')
        return new_atm_key, new_atm_iv, bal, pkt_for_card

    def withdraw(self, card_id, amount, card_pkt, atm_ctr, atm_key, atm_id, pin):
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
        aes2 = AES.new(atm_key, AES.MODE_CTR, counter=lambda:atm_ctr)
        pkt = struct.pack(">8s8s16s128s%ds" % len(card_pkt), "00000000", pin, amount, card_id, card_pkt)
        enc_pkt = "w" + atm_id + aes2.encrypt(pkt) + "EOP"
        self.ser.write(enc_pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            self._vp('withdraw: request denied')
            return False

        pkt = read_pkt()
        dec_pkt = aes2.decrypt(pkt)
        len_card_pkt = len(dec_pkt)-64
        new_atm_k, new_atm_c, bal, pkt_for_card = struct.unpack(">32s16s16s%ds" % len_card_pkt, dec_pkt)
        self._vp('withdraw: Withdrawal accepted')
        return new_atm_k, new_atm_c, bal, pkt_for_card

    def change_pin(self, old_pin, new_pin, card_pkt, card_id, atm_id, atm_aes_key, atm_aes_ctr):
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
        aes3 = AES.new(atm_aes_key, ATM.MODE_CTR, counter=lambda:atm_aes_ctr)
        pkt = struct.pack(">8s8s128s%ds" % len(card_pkt), old_pin, new_pin, card_id, card_pkt)
        enc_pkt = "c" + atm_id + aes3.encrypt(pkt) + "EOP"
        self.ser.write(enc_pkt)

        while pkt not in "ONE":
            pkt = self.ser.read()

        if pkt != "O":
            self._vp('change pin: request denied')
            return False

        pkt = read_pkt()
        dec_pkt = aes3.decrypt(pkt)
        len_pkt_for_card = len(dec_pkt)-48
        atm_key, atm_ctr, pkt_for_card = struct.unpack(">32s16s%ds" % len_pkt_for_card, dec_pkt)
        self._vp('change pin: request accepted')
        return new_atm_key, new_atm_ctr, pkt_for_card

    def provision_update(self, uuid, pin, balance, tampercode, key, iv):
        pkt = struct.pack(">128s32s16s32s32s16s", uuid, pin, balance, tampercode, key, iv)
        self.ser.write("p" + pkt)
