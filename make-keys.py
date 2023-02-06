#
# Copyright 2023 James Pace
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
from cryptography.hazmat.primitives import serialization
import cryptography.hazmat.primitives.asymmetric.ec as ec
import random

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', '-o', required=True)
    args = parser.parse_args()

    out_priv_name = args.output + '.key'
    out_pub_name = args.output + '.pub'

    # Generate the private key.
    priv_key = ec.generate_private_key(ec.SECP256R1)
    # And now the public key.
    pub_key = priv_key.public_key()

    # Serialize the private key.
    priv_key_bytes = priv_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
    with open(out_priv_name, 'wb') as priv_key_file:
        priv_key_file.write(priv_key_bytes)

    # And the public key.
    pub_key_bytes = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(out_pub_name, 'wb') as pub_key_file:
        pub_key_file.write(pub_key_bytes)

main()
