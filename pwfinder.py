import string
import hashlib
import sys
import base64
import time
import multiprocessing
##################
# FOUND PASSWORD #
#     uosuuz     #
##################
# USED FOR TESTING MD5_CRYPT FUNCTION
#import crypt

salt = "hfT7jp2q"
saltwithmd5='$1$hfT7jp2q'
keystring = "xzv"

#############################################
# USED FOR TEST length 3 password
# crypt_call = crypt.crypt('xzv',saltwithmd5)
# print 'crypted_result:' + crypt_call + '\n'
###################################################
# http://code.metager.de/source/xref/gnu/glibc/crypt/md5-crypt.c
# https://pythonhosted.org/passlib/lib/passlib.hash.md5_crypt.html
##############################################

##################################################
# SHADOW FILE TEAM 28 INFO
##################################################
#team28:$1$hfT7jp2q$X.75WJhn3pTrryOmEGcY3.:16653:0:99999:7:::
#$1$ indicates MD5 hash algorithm
#SALT: hfT7jp2q
#password hash: X.75WJhn3pTrryOmEGcY3.
#################################################


#string of all lowercase letters
l_alpha = string.lowercase
def_stdout = sys.stdout

#full crypt to crack
to_crack = '$1$hfT7jp2q$X.75WJhn3pTrryOmEGcY3.'


#passwords stored as lists
#convert to strings when printing/using as password
#convert using "".join(pwdX)
pwd6 = list("aaaaaa")
pwd5 = list("aaaaa")
pwd4 = list("aaaa")
pwd3 = list("aaa")
pwd2 = list("aa")
pwd1 = list("a")

#alphabet to use among the 4 processes
# for sixpass functions
alphat_1 = list("abcdefg")
alphat_2 = list("hijklmn")
alphat_3 = list("opqrst")
alphat_4 = list("uvwxyz")

#alphabet used to convert
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def to64 (v, n):
    ret = ''
    while (n - 1 >= 0):
        n = n - 1
	ret = ret + ITOA64[v & 0x3f]
	v = v >> 6
    return ret

#pass in password and salt
#to generate md5_crypt 
def md5_crypt(pw, salt):
    
    crypt_method = '$1$' #MD5
    if salt[:len(crypt_method)] == crypt_method:
        salt = salt[len(crypt_method):]
        

    # salt can have up to 8 characters:
    salt = string.split(salt, '$', 1)[0]
    #truncate salt if more than 8 characters
    salt = salt[:8]
    #start digest B
    #add salt and method to digest B
    ctx = pw + crypt_method + salt
    #start MD5 digest A
    final = hashlib.md5(pw + salt + pw).digest()
    #for each block of 16 bytes in the password string
    #add the first N bytes of digest B to digest A
    for pl in range(len(pw),0,-16):
        if pl > 16:
            ctx = ctx + final[:16]
        else:
            ctx = ctx + final[:pl]

    #for each bit in the binary representation of the password
    #string; starting with the lowest value bit up to and including
    # the largest-valued bit that is set to 1:
    # if current bit is set to 1, add the first character of the password to digest A
    # otherwise add NULL to digest A
    i = len(pw)
    while i:
        if i & 1:
            ctx = ctx + chr(0)
        else:
            ctx = ctx + pw[0]
        i = i >> 1
    #finish digestA
    final = hashlib.md5(ctx).digest()

    #For 1000 rounds
    # start digest C
    # if round is odd add password to digestC
    # if round is even, add prev rounds result to digC. if round 0 add digA instead
    # If the round is not a multiple of 3, add the salt to digest C.
    # If the round is not a multiple of 7, add the password to digest C.
    # If the round is even, add the password to digest C.
    # if the round is odd, add the prev rounds result to digC for round 0 add digA instead
    # Use the final value of MD5 digest C as the result for this round.
    for i in range(1000):
        digestC = ''
        if i & 1:
            digestC = digestC + pw
        else:
            digestC = digestC + final[:16]

        if i % 3:
            digestC = digestC + salt

        if i % 7:
            digestC = digestC + pw

        if i & 1:
            digestC = digestC + final[:16]
        else:
            digestC = digestC + pw
            
            
        final = hashlib.md5(digestC).digest()

# Transpose the 16 bytes of the final round's result in the following order:'
# 12,6,0,13,7,1,14,8,2,15,9,3,5,10,4,11
#then encode the resulting 16 byte string into a 22 character hash64
                                
    passwd = ''

    passwd = passwd + to64((int(ord(final[0])) << 16)
                           |(int(ord(final[6])) << 8)
                           |(int(ord(final[12]))),4)

    passwd = passwd + to64((int(ord(final[1])) << 16)
                           |(int(ord(final[7])) << 8)
                           |(int(ord(final[13]))), 4)

    passwd = passwd + to64((int(ord(final[2])) << 16)
                           |(int(ord(final[8])) << 8)
                           |(int(ord(final[14]))), 4)

    passwd = passwd + to64((int(ord(final[3])) << 16)
                           |(int(ord(final[9])) << 8)
                           |(int(ord(final[15]))), 4)

    passwd = passwd + to64((int(ord(final[4])) << 16)
                           |(int(ord(final[10])) << 8)
                           |(int(ord(final[5]))), 4)

    passwd = passwd + to64((int(ord(final[11]))), 2)


    return crypt_method + salt + '$' + passwd

#First sixpass method
#No multiprocessing used
#1 thread working through all combinations
def sixpass():
	Progress = 0.0
	print 'Sixpass BEGIN'
	for i in range(26):
		#change first character
		pwd6[0] = l_alpha[i]
		#print out how far function is from completing
		Progress = Progress + 3.84615
		print 'Progress1: ' + str(Progress) + '%\n'
		for j in range(26):
			#change second character
			pwd6[1] = l_alpha[j]
			for k in range(26):
				#change third character
				pwd6[2] = l_alpha[k]
				for l in range(26):
					#change fourth character
					pwd6[3] = l_alpha[l]
					for m in range(26):
						#change fifth character
						pwd6[4] = l_alpha[m]
						for n in range(26):
							#change sixth character
							pwd6[5] = l_alpha[n]
							#join list into string
							passwd6 = "".join(pwd6)
							copy_pw = passwd6
							generated_crypt = md5_crypt(passwd6, salt)
							if(generated_crypt == to_crack):
								#output found password to file
								f = open('sixout.txt','a')
								sys.stdout = f 
								print('Password found: ' + copy_pw +'\n')
								sys.stdout = def_stdout
								f.close()
	print 'Sixpass END'
	return

#Each process has seperate list
#Did this to avoid process editing the same list
pwd6_1 = list("aaaaaa")
pwd6_2 = list("aaaaaa")
pwd6_3 = list("aaaaaa")
pwd6_4 = list("aaaaaa")


def sixpass1():
	#store starting time of process
	start_time6_1 = time.time()
	Progress = 0.0
	print 'Sixpass1 BEGIN'
	f = open('sixout1.txt','w')
	for i in range(7):
		pwd6_1[0] = alphat_1[i]
		Progress = Progress + 14.285
		print 'Progress1: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd6_1[1] = l_alpha[j]
			for k in range(26):
				pwd6_1[2] = l_alpha[k]
				for l in range(26):
					pwd6_1[3] = l_alpha[l]
					for m in range(26):
						pwd6_1[4] = l_alpha[m]
						for n in range(26):
							pwd6_1[5] = l_alpha[n]
							passwd6 = "".join(pwd6_1)
							copy_pw = passwd6
							generated_crypt = md5_crypt(passwd6, salt)
							if(generated_crypt == to_crack):
								#if hash match output password to console
								print('Password found: ' + copy_pw +'\n')
	#calculate total runtime
	f.write("Sixpass1 runtime: " + str(time.time()-start_time6_1))
	f.close()
	print 'Sixpass1 END'
	return

def sixpass2():
	start_time6_2 = time.time()
	Progress = 0.0
	print 'Sixpass2 BEGIN'
	f = open('sixout2.txt','w')
	for i in range(7):
		pwd6_2[0] = alphat_2[i]
		Progress = Progress + 14.285
		print 'Progress2: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd6_2[1] = l_alpha[j]
			for k in range(26):
				pwd6_2[2] = l_alpha[k]
				for l in range(26):
					pwd6_2[3] = l_alpha[l]
					for m in range(26):
						pwd6_2[4] = l_alpha[m]
						for n in range(26):
							pwd6_2[5] = l_alpha[n]
							passwd6 = "".join(pwd6_2)
							copy_pw = passwd6
							value2 = md5_crypt(passwd6, salt)
							if(value2 == to_crack):
								print('Password found: ' + copy_pw +'\n')
	f.write("6_2 runtime: " + str(time.time()-start_time6_2))
	f.close()
	print 'Sixpass2 END'
	return

def sixpass3():
	start_time6_3 = time.time()
	Progress = 0.0
	print 'Sixpass3 BEGIN'
	f = open('sixout3.txt','w')
	for i in range(6):
		pwd6_3[0] = alphat_3[i]
		Progress = Progress + 16.65
		print 'Progress3: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd6_3[1] = l_alpha[j]
			for k in range(26):
				pwd6_3[2] = l_alpha[k]
				for l in range(26):
					pwd6_3[3] = l_alpha[l]
					for m in range(26):
						pwd6_3[4] = l_alpha[m]
						for n in range(26):
							pwd6_3[5] = l_alpha[n]
							passwd6 = "".join(pwd6_3)
							copy_pw = passwd6
							generated_crypt = md5_crypt(passwd6, salt)
							if(generated_crypt == to_crack):
								print('Password found: ' + copy_pw +'\n')
	f.write("6_3 runtime: " + str(time.time()-start_time6_3))
	f.close()
	print 'Sixpass3 END'
	return

def sixpass4():
	start_time6_4 = time.time()
	Progress = 0.0
	print 'Sixpass4 BEGIN'
	f = open('sixout4.txt','w')
	for i in range(6):
		pwd6_4[0] = alphat_4[i]
		Progress = Progress + 16.65
		print 'Progress4: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd6_4[1] = l_alpha[j]
			for k in range(26):
				pwd6_4[2] = l_alpha[k]
				for l in range(26):
					pwd6_4[3] = l_alpha[l]
					for m in range(26):
						pwd6_4[4] = l_alpha[m]
						for n in range(26):
							pwd6_4[5] = l_alpha[n]
							passwd6 = "".join(pwd6_4)
							copy_pw = passwd6
							value2 = md5_crypt(passwd6, salt)
							if(value2 == to_crack):
								print('Password found: ' + copy_pw +'\n')
	f.write("6_4 runtime: " + str(time.time()-start_time6_4))
	f.close()
	print 'Sixpass4 END'
	return

def fivepass():
	Progress = 0.0
	passwd5 = ""
	print 'FivePass BEGIN'
	for i in range(26):
		pwd5[0] = l_alpha[i]
		Progress = Progress + 3.84615
		print 'Progress: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd5[1] = l_alpha[j]
			for k in range(26):
				pwd5[2] = l_alpha[k]
				for l in range(26):
					pwd5[3] = l_alpha[l]
					for m in range(26):
						pwd5[4] = l_alpha[m]
						passwd5 = "".join(pwd5)
						copy_pw = passwd5
						generated_crypt = md5_crypt(passwd5, salt)
						if(generated_crypt == to_crack):
							f = open('fiveout.txt','a')
							sys.stdout = f 
							print('Password found: ' + copy_pw +'\n')
							sys.stdout = def_stdout
							f.close()
	print 'FivePass END'
	return

def fourpass():
	Progress = 0.0
	print 'Fourpass BEGIN'
	for i in range(26):
		pwd4[0] = l_alpha[i]
		Progress = Progress + 3.84615
		print 'Progress: ' + str(Progress) + '%\n'
		for j in range(26):
			pwd4[1] = l_alpha[j]
			for k in range(26):
				pwd4[2] = l_alpha[k]
				for l in range(26):
					pwd4[3] = l_alpha[l]
					passwd4 = "".join(pwd4)
					copy_pw = passwd4
					generated_crypt = md5_crypt(passwd4, salt)
					if(generated_crypt == to_crack):
						f = open('fourout.txt','a')
						sys.stdout = f 
						print('Password found: ' + copy_pw +'\n')
						sys.stdout = def_stdout
						f.close()
	print 'Fourpass END'
	return

def threepass():
	start_time3_1 = time.time()
	print 'Threepass BEGIN'
	f = open('threeout.txt','w')
	for i in range(26):
		pwd3[0] = l_alpha[i]
		for j in range(26):
			pwd3[1] = l_alpha[j]
			for k in range(26):
				pwd3[2] = l_alpha[k]
				passwd3 = "".join(pwd3)
				copy_pw = passwd3
				generated_crypt = md5_crypt(passwd3, salt)
				if(generated_crypt == to_crack):
					print 'generated_crypt: ' + generated_crypt + '\n'
					print 'to_crack: ' + to_crack + '\n'
					print('Password found: ' + copy_pw +'\n')
	f.write("3_1 runtime: " + str(time.time()-start_time3_1))
	f.close()
	print 'Threepass END'
	return

#generate length 2 password
#join to convert to string and print result
def twopass():
	print 'Twopass BEGIN'
	f = open('twoout.txt','w')
	sys.stdout = f
	for i in range(26):
		pwd2[0] = l_alpha[i]
		for j in range(26):
			pwd2[1] = l_alpha[j]
			passwd2 = "".join(pwd2)
			copy_pw = passwd2
			generated_crypt = md5_crypt(passwd2, salt)
			if(generated_crypt == to_crack):
				print('Password found: ' + copy_pw +'\n')
	sys.stdout = def_stdout
	f.close()
	print 'Twopass END'
	return

def onepass():
	print 'Onepass BEGIN'
	f = open('oneout.txt','w')
	sys.stdout = f 
	for j in range(26):
		pwd1[0] = l_alpha[j]
		passwd1 = "".join(pwd1)
		copy_pw = passwd1
		generated_crypt = md5_crypt(passwd1, salt)
        if(generated_crypt == to_crack):
			print('Password found: ' + copy_pw +'\n')
	sys.stdout = def_stdout
	f.close()
	print 'Onepass END'
	return

def eightpass():
	# NOPE NOT EVER GOING TO FINISH
	return

#function calls
#Single thread NOT multiprocess
onepass()
twopass()
threepass()
fourpass()
fivepass()

#Multiprocess 6-length password
procs = []
p1 = multiprocessing.Process(target = sixpass1)
procs.append(p1)
p2 = multiprocessing.Process(target = sixpass2)
procs.append(p2)
p3 = multiprocessing.Process(target = sixpass3)
procs.append(p3)
p4 = multiprocessing.Process(target = sixpass4)
procs.append(p4)
p1.start()
p2.start()
p3.start()
p4.start()
