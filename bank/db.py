""" DB
This module implements an interface to the bank_server database.
"""

import json
import os.path


class DB(object):
    """Implements a Database interface for the bank server and admin interface"""
    def __init__(self, db_path="bank.json"):
        self.path = db_path

    def close(self):
        """close the database connection"""
        pass

    def init_db(self):
        """initialize database with file at filepath"""
        with open(self.path, 'w') as f:
            f.write(json.dumps({'atms': {}, 'cards': {}}))

    def exists(self):
        return os.path.exists(self.path)

    def modify(self, table, k, subks, vs):
        if not self.exists():
            print "Creating new database..."
            self.init_db()
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            for subk, v in zip(subks, vs):
                if k not in db[table]:
                    db[table][k] = {}
                db[table][k][subk] = v
        except KeyboardInterrupt:
            return False

        with open(self.path, 'w') as f:
            f.write(json.dumps(db))

        return True

    def read(self, table, k, subk):
        with open(self.path, 'r') as f:
            db = json.loads(f.read())

        try:
            return db[table][k][subk]
        except KeyError:
            return None

    ############################
    # BANK INTERFACE FUNCTIONS #
    ############################

    def set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal"], [balance])

    def get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal")

    def get_atm(self, atm_id):
        """get atm_id of atm: atm_id
        this is an obviously dumb function but maybe it can be expanded...

        Returns:
            (string or None): Returns atm_id on Success. None otherwise.
        """
        return 1000

    def get_atm_num_bills(self, atm_id):
        """get number of bills in atm: atm_id

        Returns:
            (string or None): Returns num_bills on Success. None otherwise.
        """
        return 1000

    def set_atm_num_bills(self, atm_id, num_bills):
        """set number of bills in atm: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return True

    #############################
    # ADMIN INTERFACE FUNCTIONS #
    #############################

    def admin_create_account(self, card_id, pin, amount, tampercode, key, iv):
        """create account with account_name, card_id, and amount

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify('cards', str(card_id), ["pin (hashed)", "bal (aes)", "tamper code (hash)", "key (definitely encrypted)", "iv (also encrypted)"], [str(pin), str(amount), str(tampercode), str(key), str(iv)])


    def admin_create_atm(self, atm_id, atm_aes_key, atm_aes_ctr):
        """create atm with atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, ["nbills", "ATM AES key", "ATM AES counter"], [128, atm_aes_key, atm_aes_ctr])

    def admin_get_balance(self, card_id):
        """get balance of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "bal (aes)")

    def admin_set_balance(self, card_id, balance):
        """set balance of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["bal (aes)"], [balance])

    def admin_get_pin(self, card_id):
        """get pin of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "pin (hashed)")

    def admin_set_pin(self, card_id, pin):
        """set pin of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["pin (hashed)"], [pin])

    def admin_get_tamper(self, card_id):
        """get tamper code of account: card_id

        Returns:
            (string or None): Returns balance on Success. None otherwise.
        """
        return self.read("cards", card_id, "tamper code (hash)")

    def admin_set_tamper(self, card_id, code):
        """set tamper code of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["tamper code (hash)"], [code])

    def admin_set_card_key(self, card_id, card_key):
        """set AES key for next card transaction of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["key (definitely encrypted)"], [card_key])

    def admin_get_card_key(self, card_id):
        """get AES key for card transaction of account: card_id

        Returns:
            (string or None): Returns AES key on Success. None otherwise.
        """
        return self.read("cards", card_id, "key (definitely encrypted)")

    def admin_set_card_iv(self, card_id, card_iv):
        """set AES counter for next card transaction of account: card_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("cards", card_id, ["iv (also encrypted)"], [card_iv])

    def admin_get_card_iv(self, card_id):
        """get AES counter for card transaction of account: card_id

        Returns:
            (string or Nona): Returns AES counter on Success. None otherwise.
        """
        return self.read("cards", card_id, "iv (also encrypted)")

    def admin_set_atm_key(self, atm_id, atm_key):
        """set AES key for next ATM transaction of ATM: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, ["ATM AES key"], [atm_key])

    def admin_get_atm_key(self, atm_id):
        """get AES key for ATM transaction of ATM: atm_id

        Returns:
            (string or None): Returns AES key on Success. None otherwise.
        """
        return self.read("atms", atm_id, "ATM AES key")

    def admin_set_atm_iv(self, atm_id, atm_iv):
        """set AES counter for next ATM transaction of ATM: atm_id

        Returns:
            (bool): Returns True on Success. False otherwise.
        """
        return self.modify("atms", atm_id, ["ATM AES counter"], [atm_iv])

    def admin_get_atm_iv(self, atm_id):
        """get AES counter for atm transaction of atm: atm_id

        Returns:
            (string or Nona): Returns AES counter on Success. None otherwise.
        """
        return self.read("atms", atm_id, "ATM AES counter")
