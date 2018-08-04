# ATM Transfer Protocol - Team TOP SECRET
### Kieran O'Connor, Ted Clifford, Charlotte Fries, Yasmine Calvo, Marcus Hardy, Evan Loconto

## Description
This is a protocol designed to fufuill the requirements of the eCTF ATM challenge (found here: https://mitrecyberacademy.org/competitions/embedded/17-3701-2.2018.01.17-eCTF%20Challenge-v1.0.pdf). Our team participated in this challenge as a part of MIT's Lincoln Laboratory Summer Program: Beaverworks Summer Institute. Our challenge was to design a system to securely make bank transfers using three components: a Cyprus PSoC (Model: CY84245AXI-483), a BeagleBone Black computer, and a traditional computer. These devices work together to transfer information in order to authorize the access to a user's bank account. Our system uses 2 factor authentication, requiring the user to enter a PIN, along with and ATM Card. The purpose of this challenge was to show us the process of designing a secure protocol, then implimenting it in the real world, using real components.

## Components
**PSoC**: This programmable embedded system functions as the ATM Card that the final user would carry around. It stores the account number, an anti-tampering protocol, as well as methods for secure comminication. The card is written in C.

**BeagleBone**: The credit-card sized computer represents the ATM, which the card and the bank interfaces with. It runs python scripts for encrypting data like the PIN and card information, as well as providing an interface for the user. All communications in and out of this device are encrypted.

**Computer**: This represents the bank side of the system. The bank holds a database of users and ATMs, and interfaces with these in Python. It recieves all requests from the ATM, and is able to decrypt it's requests. Once a user and card is verified as safe, it responds to the request. After each transaction, new encryption devices are distributed to each device, preventing certain attacks on the system.


