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
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.asymmetric.ec as ec
import cryptography
import json
from sshpubkeys import SSHKey

def main():
    parser = argparse.ArgumentParser(description="Check an intoto/slsa signature from Tekton against a public key.")
    parser.add_argument('public_key', help="Public key in pem format from cosign.")
    parser.add_argument('sig_file', help="Signature file from Tekton.")
    parser.add_argument('--payload', '-p', action='store_true', help="Print the payload if it is signed.")
    args = parser.parse_args()

    # Open the public key.
    key = None
    with open(args.public_key, 'rb') as pubkey_file:
        key = serialization.load_pem_public_key(pubkey_file.read())

    # Open the signed attestation.
    sig_json = None
    with open(args.sig_file, 'rb') as sig_file:
        sig_json = json.loads(base64.b64decode(sig_file.read(), validate=True))

    if not sig_json or not key:
        print("I don't have a valid payload or key?")
        exit(-2)

    # Get the signature we're checking from the signed attestation,
    # for the provided public key.
    pub_key_fingerprint = get_fingerprint(key)
    signature = None
    for sig_set in sig_json['signatures']:
        if sig_set['keyid'] == pub_key_fingerprint:
            signature = sig_set['sig']
    if not signature:
        print("I don't have a signature for the provided key in this signature file?")
        exit(-3)

    # Convert from the stuff in the signed attestation to what actually
    # gets signed.
    signature = base64.b64decode(signature.encode('utf-8'), validate=True)
    payload = base64.b64decode(sig_json['payload'].encode('utf-8'), validate=True)
    header = sig_json['payloadType'].encode('utf-8')
    combined_payload = combine_payload(header, payload)

    # Now verify it.
    try:
        key.verify(signature=signature,
                data=combined_payload,
                signature_algorithm=ec.ECDSA(hashes.SHA256()))
    except cryptography.exceptions.InvalidSignature:
        print("Failed signature check!")
        exit(-1)

    # Check the payload type now that we've checked the signature.
    if sig_json['payloadType'] != "application/vnd.in-toto+json":
        print("Signature passed, but not the payload type I was expecting?")
        exit(-4)

    # Either print the payload or that things went well.
    if not args.payload:
        print('Success!')
    else:
        # TODO: Pretty print this, including the shell script.
        print(json.loads(payload.decode('utf-8')))
    exit(1)

def get_fingerprint(key):
    # Convert to an ssh key and then hash it.
    key_bytes = key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)
    ssh_key = SSHKey(key_bytes.decode("utf-8"))
    ssh_key.parse()
    return ssh_key.hash_sha256()

def combine_payload(header_in, body_in):
    # https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
    # "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    dsse = bytearray("DSSEv1".encode('utf-8'))
    sp = bytearray(b'\x20')
    header = bytearray(header_in)
    body = bytearray(body_in)
    len_type = bytearray(str(len(header)).encode('ascii'))
    len_body = bytearray(str(len(body)).encode('ascii'))

    pae = dsse + sp + len_type + sp + header + sp + len_body + sp + body

    return bytes(pae)


main()
