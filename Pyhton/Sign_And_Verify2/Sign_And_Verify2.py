import binascii
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

class MyDigest:
    def __init__(self,hash):
        self.hash=hash
    def __call__(self):
        return self.hash


class MyHash:
    def __init__(self,hash):
        self.digest = MyDigest(hash)
    oid = '2.16.840.1.101.3.4.2.1'

# Provide Private Key
key_integer = int("0x2598E6506CC0724DA0D50940907193C0238CC3A2A2344D3C653EE0DD03F6B710",0)
key = ECC.construct(curve='P-256',d=key_integer)
print ("Used Signing Private Key:")
print(key)
print(key.public_key())

# Provide to-be-signed data if desired
address = binascii.unhexlify("00000001")
length  = binascii.unhexlify("00000004")
print()
print("Address:")
print(binascii.hexlify(address))
print("Length:")
print(binascii.hexlify(length))
h = SHA256.new(address)
h.update(length)
f = open("bfaf849a8a251d25b6ca6fd162f73c1a15e23aadb489715449de440cdbc5b12200.bin", "rb")
h.update(f.read())
f.close()
f = open("bfaf849a8a251d25b6ca6fd162f73c1a15e23aadb489715449de440cdbc5b12200.bin", "rb")
Hfile = SHA256.new(f.read())
f.close()
print("SHA256 of Bin-File:")
print(Hfile.hexdigest())
print("Overall-SHA256")
print(h.hexdigest())

## Provide Hash instead of input message if desired
#signhash = MyHash(binascii.unhexlify("32d3e084895c706895e107f30de0fdc809b252dbe507f27167a73953879208d2"))
#print()
#print("Provided input-hash:")
#print(binascii.hexlify(signhash.digest()))


signer = DSS.new(key, 'fips-186-3','der')
#Uncomment the folloing line if input-message is given
signature = signer.sign(h)
##Uncomment the following line if input-SHA256-Hash is given
##signature = signer.sign(signhash)
#print(signature)
print()
print("Resultung Signature:")
print(binascii.hexlify(signature))

###########################################

#Provide Public Key for Verification
key = ECC.construct(curve='P-256', point_x = int("0xc19b0c577217fea5900b18e9bcd72211f8e3188cfd85164d1de36687f216d81f",0), point_y = int("0x6d33885b57b080215ded184314397afeb9875a39ad93e4009f8c2f1b0803b2d8",0))
print()
print ("Used Verification Public Key:")
print(key)

#Provide Signature
signature = binascii.unhexlify("b903a8bc280ec085a4e8b46c92370d096c6f2608fdc9cd6e1504559219bc7cf526aa4ff63eba1ddb2b629a89d454412fd65c54b0fdcba0c74a3d40faf5c9f501")
print()
print("Given Signature:")
print(binascii.hexlify(signature))

# Provide to-be-verified data if desired
address = binascii.unhexlify("00000002")
length  = binascii.unhexlify("00000004")
print()
print("Address:")
print(binascii.hexlify(address))
print("Length:")
print(binascii.hexlify(length))                                                                                                                                                                                                      
print("Length in decimal:")
print(int(binascii.b2a_hex(length),16))

h = SHA256.new(address)
h.update(length)
f = open("bfaf849a8a251d25b6ca6fd162f73c1a15e23aadb489715449de440cdbc5b12200.bin", "rb")
h.update(f.read())
f.close()

f = open("bfaf849a8a251d25b6ca6fd162f73c1a15e23aadb489715449de440cdbc5b12200.bin", "rb")
Hfile = SHA256.new(f.read())
f.close()
print("SHA256 of Bin-File:")
print(Hfile.hexdigest())

print("Overall-SHA256")
print(h.hexdigest())


# Provide Hash instead of input message for verification if desired
#verifyhash = MyHash(binascii.unhexlify("5faa6dd49eb31b0920dfea0568df34330217d110a3aa2177de5437193cc1a5b4"))
#print()
#print("Provided verfication-hash:")
#print(binascii.hexlify(verifyhash.digest()))

#Prefix = binascii.unhexlify("302E300A06082A8648CE3D0403020420")
#ModifiedHash = SHA256.new(Prefix)
#ModifiedHash.update(h.digest())
#print()
#print("Provided Prefix:")
#print(binascii.hexlify(Prefix))
#print()
#print("Provided Input for SHA256-with-ECDSA256")
#print(binascii.hexlify(Prefix) + binascii.hexlify(h.digest()))
#print()
#print("Provided modified-hash:")
#print(binascii.hexlify(ModifiedHash.digest()))


#Uncomment the following line if input is additionally hashed
hInterim = SHA256.new(binascii.unhexlify(h.hexdigest()))
print()
print("Additional hashing of given input:")
print(hInterim.hexdigest())

#verifier = DSS.new(key, 'fips-186-3', 'binary')
verifier = DSS.new(key, 'fips-186-3', 'der')
try:
    #Uncomment the following line if verification-message is given
    verifier.verify(h, signature)
    #Uncomment the following line if input is additionally hashed
    #verifier.verify(hInterim, signature)
    #Uncomment the following line if verification-SHA256-hash is given
    #verifier.verify(verifyhash, signature)
    #Uncomment the following line if modified-SHA256-hash is given
    #verifier.verify(ModifiedHash, signature)
    print("=================================The signature is authentic.======================================")
except ValueError:
    print("The signature is NOT authentic.")


