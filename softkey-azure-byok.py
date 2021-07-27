
import json
import base64
import subprocess 
import argparse
import os

SCHEMA_VERSION = "1.0.0"
OPENSSL_V110 = "~/local/bin/openssl.sh"

OUT_DIR = "./artifacts"
PRIVATE_KEY_PATH = "{}/private_key.pem".format(OUT_DIR)
TARGET_KEY_PATH = "{}/target_key.key".format(OUT_DIR)
TEMP_AES_KEY_PATH = "{}/temp_aes_key.key".format(OUT_DIR)
WRAPPED_TEMP_AES_KEY = "{}/wrapped_temp_aes_key.bin".format(OUT_DIR)
WRAPPED_TARGET_KEY_PATH = "{}/wrapped_target_key.bin".format(OUT_DIR)


class SoftKEYAzureByok(object):

	def setup(self, args):
		self.azure_kek_id = args["kid"]
		self.target_key_size = args["key_size"]
		self.target_byok_file_name = args["out_byok"]
		self.wrapping_key_file_name =	args["kek_in"]

		self.clean()
		_dir = "{}".format(OUT_DIR)
		try:
			os.makedirs(_dir)
		except FileExistsError:
			pass

	def clean(self):
		_dir = "{}".format(OUT_DIR)
		cmd = "rm -rf " + _dir
		subprocess.check_output(cmd, shell = True)
	 
	def generate_byok_file(self):
		# JSON header
		header = {
			"kid": self.azure_kek_id,
			"alg": "dir",
			"enc": "CKM_RSA_AES_KEY_WRAP"
		}

		with open(WRAPPED_TEMP_AES_KEY, mode='rb') as file:
			wrapped_wrapping_key = file.read()
		with open(WRAPPED_TARGET_KEY_PATH, mode='rb') as file:
			wrapped_target_key = file.read()

		byok = {
			"schema_version": SCHEMA_VERSION,
			"header": header,
			"ciphertext": base64.urlsafe_b64encode(wrapped_wrapping_key + wrapped_target_key).decode(),
      "generator": "SoftKEY BYOK Tool"
		}

		with open(self.target_byok_file_name.format(OUT_DIR), 'w') as f:
			json.dump(byok, f, indent=2)
			

	def do_byok(self):

		# Generate a private key.
		cmd = OPENSSL_V110 + " genrsa -out " + PRIVATE_KEY_PATH + " " + self.target_key_size
		subprocess.check_output(cmd, shell = True)

		# Convert the private key to PKCS8 DER format.
		cmd =  OPENSSL_V110 + " pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in " +  PRIVATE_KEY_PATH + " -out " + TARGET_KEY_PATH
		subprocess.check_output(cmd, shell = True)

		# Generate a temporary AES key.
		cmd = OPENSSL_V110 + " rand -out " + TEMP_AES_KEY_PATH + " 32"
		subprocess.check_output(cmd, shell = True)

		# Wrap the temporary AES key by using RSA-OAEP with SHA-256.
		cmd = OPENSSL_V110 + " pkeyutl -encrypt -in " + TEMP_AES_KEY_PATH + " -inkey " + self.wrapping_key_file_name + " -pubin -out " + WRAPPED_TEMP_AES_KEY + " -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1"
		subprocess.check_output(cmd, shell = True)

		# Wrap the target RSA key.
		cmd = "(hexdump -v -e '/1 \"%02x\"' < " + TEMP_AES_KEY_PATH + ")"
		temp_aes_key_hexdump = subprocess.check_output(cmd, shell = True)
		cmd = OPENSSL_V110 + " enc -id-aes256-wrap-pad -iv A65959A6 -K " + temp_aes_key_hexdump.decode('ascii') + " -in " + TARGET_KEY_PATH + " -out " + WRAPPED_TARGET_KEY_PATH
		subprocess.check_output(cmd, shell = True)


def main():
	soft_key_azure_byok = SoftKEYAzureByok()
	parser = argparse.ArgumentParser(description="SoftKEY Azure BYOK tool for importing protected keys to Azure Key Vault")
	parser.add_argument("--kid", help="Azure KEK Identifier (Full URL)", required=True)
	parser.add_argument("--key-size", help="RSA key size 2048, 3072, 4096", required=True)
	parser.add_argument("--out-byok", help="BYOK File (File name full path)", required=True)
	parser.add_argument("--kek-in", help="Azure KEK for BYOK (File name full path)", required=True)
	args = parser.parse_args()
	soft_key_azure_byok.setup(vars(args))
	soft_key_azure_byok.do_byok()
	soft_key_azure_byok.generate_byok_file()

if __name__ == '__main__':
	main()