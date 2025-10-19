"""
Configuration file for authentication protocol simulation

This file specifies all key parameters used across the project:
- Simulation settings
- Attack behaviour
- Network Configurations
- Dataset logging options
"""

#Simulation settings
NUM_SESSIONS = 500 #Total number of authentication settings per run
ATTACK_RATE = 0.20 #Fraction of sessions with attack (0.0 - 1.0)
REPLAY_PROB = 0.6 #Fraction of replay attacks
RANDOM_GUESS_PROB = 0.4 #Remianing fraction are random-guess attacks
THREAD_COUNT = 5 #Parallel threads for concurrent sessions
SEED = 42 #For reproducibility

#Protocol Settings
KEY_SIZE = 32 #Bytes for shared secret key
NONCE_SIZE = 16 #Bytes for nonce
HASH_FUNCTION = "SHA256" #Currently only SHA256 used
RESPONSE_DELAY = (0.01, 0.1) #Simulated response delay range in seconds

#Network Configuration
BOB_HOST = "127.0.0.1" #Server host
BOB_PORT = 5000 #Server port for Bob
ALICE_PORT_START = 6000 #Base port for Alice instances
BUFFER_SIZE = 4096 #Socket buffer size in bytes
CONNECTION_TIMEOUT = 5 #Seconds before socket timeout

#Data Logging and Storage
DATA_DIR = "data/results/" #Folder to save datasets
LOG_DIR = "data/logs/" #Folder for individual session logs
TEMP_DIR = "data/temp/" #Temporary socket logs or partial messages
DATASET_FILENAME = "auth_dataset.csv"

SAVE_RAW_MESSAGES = True #If True, store message-level traces for analysis
SAVE_INTERNAL = 100 #Save dataset to file every N sessions

#Attacker settings
ENABLE_ATTACKER_THREAD = True #Whether to spawn an active attacker
ATTACKER_BEHAVIOR = "mixed" #Options: "passive", "replay", "random_guess", "mixed"
ATTACKER_DELAY = (0.01, 0.05) #Simulated delay in attack response (seconds)
