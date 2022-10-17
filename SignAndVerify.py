import binascii
import os
import string
from enum import Enum
from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import eddsa, DSS, pkcs1_15, PKCS1_PSS, PKCS1_v1_5, pss


print ("Versiion 4 olacak ")
print ("Versiion 3 yaptim")

print ("Versiion 5 2Zqwief")

class Signature(Enum):
    RSA1k = 1
    RSA3k = 3
    RSA8k = 8
    RSA16k = 16
    ECDSA = 40
    ECC384 = 41
    ECC512 = 42


class Hash(Enum):
    SHA1 = 1
    SHA256 = 256
    SHA384 = 384
    SHA512 = 512


def GetSigner(key_file_p8: string):
    file = open(key_file_p8, "rb")
    file.seek(0x23)
    private_key_read = file.read(32)
    file.close
    print("Private key:", private_key_read.hex())
    private_key = int.from_bytes(private_key_read, 'big')
    ecc_private_key = ECC.construct(curve='P-256', d=private_key)
    return DSS.new(ecc_private_key, 'fips-186-3', 'der')


def GetFileContent(file_name: string):
    file = open(file_name, "rb")
    file_content = file.read()
    file.close()
    return file_content


def GetHash(method: Hash, file_name: string, address: int):
    file_length = os.path.getsize(file_name)
    file_content = GetFileContent(file_name)
    print("Address:", address)
    print("Length:", file_length)
    print("Content:", file_content.hex())
    address_bytes = address.to_bytes(4, 'big')
    file_length_bytes = file_length.to_bytes(4, 'big')

    if method == Hash.SHA1:
        sha_hash = SHA1.new(address_bytes)
    elif method == Hash.SHA256:
        sha_hash = SHA256.new(address_bytes)
    elif method == Hash.SHA384:
        sha_hash = SHA384.new(address_bytes)
    elif method == Hash.SHA512:
        sha_hash = SHA512.new(address_bytes)
    else:
        print("Unsupported hash function:", method)
        return

    sha_hash.update(file_length_bytes)
    sha_hash.update(file_content)
    print(method, "(Address | Length | Content)")
    print(sha_hash.hexdigest())
    return sha_hash


def GetEccKey(cert_file: string):
    file_content = GetFileContent(cert_file)
    return ECC.import_key(file_content)


def GetRsaKey(cert_file: string):
    file_content = GetFileContent(cert_file)
    return RSA.import_key(file_content)


def verify_signature(signature_method: Signature, hash_method: Hash, cert_file: string, bin_file: string, address: int, expected_signature: string):
    print("bin file:", bin_file)
    hash = GetHash(hash_method, bin_file, address)

    print("verify signature:")
    print(expected_signature)
    expected_signature_bytes = binascii.unhexlify(expected_signature)

    print("certificate file:", cert_file)

    if signature_method == Signature.ECDSA or signature_method == Signature.ECC384 or signature_method == Signature.ECC512:
        key = GetEccKey(cert_file)
        verifier = DSS.new(key, 'fips-186-3', 'binary')
    elif signature_method == Signature.RSA1k or signature_method == Signature.RSA3k or signature_method == Signature.RSA8k or signature_method == Signature.RSA16k:
        key = GetRsaKey(cert_file)
        verifier = pkcs1_15.new(key)
        # verifier = PKCS1_PSS.new(key)
        # verifier = PKCS1_v1_5.new(key)
    else:
        print("Signature", signature_method, "not supported")

    try:
        verifier.verify(hash, expected_signature_bytes)
        print("=================================The signature is authentic.======================================")
    except ValueError:
        print("=================================The signature is NOT authentic.======================================")


# ECDSA mit SHA256
logical_block_index = 0x71
bin_file_name = "block3.bin"

hash_method = Hash.SHA256
signature_method = Signature.ECDSA
cert_file_name = "FDSProject_2272_E.cer"

# Signatur z.B. aus ODXCreate
expected_signature = "C93AD87B30EF9D843E155ADD7A6921371DCE35E4A83BF7D34B7CDFA7D5A67169CA25F3F4DCAB94942B8D87218B94E8C9ABDDC97D1027E4DC00E5C1411573821D"
verify_signature(signature_method, hash_method, cert_file_name, bin_file_name,
                 logical_block_index, expected_signature)

# RSA3k mit SHA1
hash_method = Hash.SHA1
signature_method = Signature.RSA3k
cert_file_name = "FDSProject_1989_E.cer"
expected_signature = "05F4A9862854F15CAB473524A39E3E12CA854BD27866740B05F7C0CD329BA3E3A82E18861C47478001A1C6843EBB8C555804E2185BE6B0A9DEFDE22592D9D4DE898AF4004803243F77ABE2769AA896E49273E68DF3EAA5D4EF2F0EF2B8C6D7B1D92A44354D601CC66301C3DAE9FA462135E471C5EDE801B0B3D25269DDE2CCD3DED628B05F079BD6EA9B64172E9A55F21895687B91B0F0BD1234CD9F2A94EB34D78BAF31748912A605A1BC29203F2D7CB122183E44259E2BECEA157FD21E4A16FD56EE5C84DEE7DD21B075F0CBBDD380B283D85C08C8B5792B6E724FE27F2E284F96D2D5568A448FF83947E0CE6E5BE9F1F06AA8D705B59B86E38923C6150BC50B97EAF4F04FCAE209461ADBB07216AD36922120615DE40C2BB543B12B1D91A7DB16C7ADC78F6BFB72C284641C1EBE0A31822900A993D0BD36B055F2C15CE753ED4E21146EC80E4ADA09FC03F18596BB78585468FF15E90EA342487CDF3D2391D3B0C5392A18B3C33ADB709D1BEE2A27CFB4C1BA97024408687329564111218A"
verify_signature(signature_method, hash_method, cert_file_name, bin_file_name,
                 logical_block_index, expected_signature)

# RSA1k mit SHA1
signature_method = Signature.RSA1k
cert_file_name = "FDSProject_1264_E.cer"
expected_signature = "68C61B4EDD602F7A2BC45307E08F11EDB062CB89C7D61EA30D650A8BDC74AA5CDFC77C36FA6628C3068AD3AB8D46F9A9B81D942FFB70562E6DBC5886E6E043347FC3936DDC4D89D62B1B67D461BBAF754CA5115D066A0E498BF6A1A597572CE0F7601E7BD370D929F04BF0F193E33426E0F42D0617D49D63B84C8A27DE989780"

verify_signature(signature_method, hash_method, cert_file_name, bin_file_name,
                 logical_block_index, expected_signature)
