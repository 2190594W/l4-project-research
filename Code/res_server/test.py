from __future__ import print_function
import pyopenabe, base64, binascii

print("Testing Python bindings for PyOpenABE...")

openabe = pyopenabe.PyOpenABE()

cpabe = openabe.CreateABEContext("CP-ABE")

cpabe.generateParams()

# msk_file = open("org1.msk.cpabe", "rb")
# msk = msk_file.read()
# msk_file.close()
# mpk_file = open("org1.mpk.cpabe", "rb")
# mpk = mpk_file.read()
# mpk_file.close()

input_file = open("input.txt", "rb")
pt1 = input_file.read()
input_file.close()

print(pt1)

print("read the param files")

# msk = msk.split(b'-----')[2].strip()
# mpk = mpk.split(b'-----')[2].strip()

# cpabe.importSecretParams(msk)
# cpabe.importPublicParams(mpk)

cpabe.keygen("|two|three|", "alice")

ct = cpabe.encrypt("((one or two) and three)", pt1)
print("ABE CT: ", len(ct))

pt2 = cpabe.decrypt("alice", ct)
print("PT: ", pt2)
assert pt1 == pt2, "Didn't recover the message!"

msk2 = cpabe.exportSecretParams()

print("Testing key import")

msk = cpabe.exportSecretParams()
mpk = cpabe.exportPublicParams()
uk = cpabe.exportUserKey("alice")
uk2 = cpabe.exportUserKey("luke")

cpabe2 = openabe.CreateABEContext("CP-ABE")

cpabe2.importSecretParams(msk)
cpabe2.importPublicParams(mpk)
cpabe2.importUserKey("alice", uk)

ct = cpabe2.encrypt("((one or two) and three)", pt1)
print("ABE CT: ", len(ct))

pt2 = cpabe2.decrypt("alice", ct)
print("PT: ", pt2)
assert pt1 == pt2, "Didn't recover the message!"

cpabe3 = openabe.CreateABEContext("CP-ABE")

cpabe3.importPublicParams(mpk)
cpabe3.importUserKey("alice", uk)

pt3 = cpabe3.decrypt("alice", ct)
print("PT: ", pt3)
assert pt1 == pt3, "Didn't recover the message!"

cpabe4 = openabe.CreateABEContext("CP-ABE")

cpabe4.generateParams()
cpabe4.importPublicParams(mpk)
cpabe4.importUserKey("alice", uk)

out_file = open("test_output.cpabe", "wb")
ciphertext = b'-----BEGIN ABE CIPHERTEXT BLOCK-----\n' + mpk + b'\n-----END ABE CIPHERTEXT BLOCK-----\n'
ciphertext += b'-----BEGIN CIPHERTEXT BLOCK-----\n' + ct + b'\n-----END CIPHERTEXT BLOCK-----'
out_file.write(ciphertext)
out_file.close()
out_file = open("test.mpk.cpabe", "wb")
master_public_key = b'-----BEGIN MASTER PUBLIC KEY BLOCK-----\n' + mpk + b'\n-----END MASTER PUBLIC KEY BLOCK-----\n'
out_file.write(master_public_key)
out_file.close()
out_file = open("test.msk.cpabe", "wb")
master_secret_key = b'-----BEGIN MASTER SECRET KEY BLOCK-----\n' + msk + b'\n-----END MASTER SECRET KEY BLOCK-----\n'
out_file.write(master_secret_key)
out_file.close()
out_file = open("test2.msk.cpabe", "wb")
master_secret_key = b'-----BEGIN MASTER SECRET KEY BLOCK-----\n' + msk2 + b'\n-----END MASTER SECRET KEY BLOCK-----\n'
out_file.write(master_secret_key)
out_file.close()
out_file = open("test_userkey.key", "wb")
userkey = b'-----BEGIN USER PRIVATE KEY BLOCK-----\n' + uk + b'\n-----END USER PRIVATE KEY BLOCK-----\n'
out_file.write(userkey)
out_file.close()
out_file = open("test_userkey2.key", "wb")
userkey = b'-----BEGIN USER PRIVATE KEY BLOCK-----\n' + uk2 + b'\n-----END USER PRIVATE KEY BLOCK-----\n'
out_file.write(userkey)
out_file.close()

pt4 = cpabe4.decrypt("alice", ct)
print("PT: ", pt4)
assert pt1 == pt4, "Didn't recover the message!"

print("CP-ABE Success!")


# pke = openabe.CreatePKEContext()
#
# pke.keygen("user1")
#
# ct1 = pke.encrypt("user1", pt1)
# print("PKE CT: ", len(ct1))
#
# pt2 = pke.decrypt("user1", ct1)
# assert pt1 == pt2, "Didn't recover the message!"
# print("PKE Success!")
#
#
# pksig = openabe.CreatePKSIGContext()
#
# pksig.keygen("user2")
#
# sig = pksig.sign("user2", pt1)
# print("PKSIG: ", len(sig))
#
# if pksig.verify("user2", pt1, sig):
#     print("PKSIG Success!")
# else:
#     print("ERROR during verify!")
#
#
# kpabe = openabe.CreateABEContext("KP-ABE")
#
# kpabe.generateParams()
#
# kpabe.keygen("((one or three) and date < April 18, 2018)", "bob")
#
# ct = kpabe.encrypt("|one|date=February 1, 2018|two", pt1)
# print("KP-ABE CT size: ", len(ct))
#
# pt2 = kpabe.decrypt("bob", ct)
# print("PT: ", pt2)
# assert pt1 == pt2, "Didn't recover the message!"
#
# print("Testing key imports")
# msk = kpabe.exportSecretParams()
# mpk = kpabe.exportPublicParams()
# uk = kpabe.exportUserKey("bob")
#
# kpabe2 = openabe.CreateABEContext("KP-ABE")
#
# kpabe2.importSecretParams(msk)
# kpabe2.importPublicParams(mpk)
# kpabe2.importUserKey("bob", uk)
#
# ct = kpabe.encrypt("|one|date=February 1, 2018|two", pt1)
# print("KP-ABE CT size: ", len(ct))
# pt2 = kpabe.decrypt("bob", ct)
# assert pt1 == pt2, "Didn't recover the message!"
#
# print("KP-ABE Success!")
print("All tests passed!")
