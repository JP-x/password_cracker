# password_cracker
Computer Security project which generates the plain text password from an encrypted password.

Can be used on an encrypted password from an /etc/shadow file from a Linux system.

Assumptions:
md5 encryption method used on passwords.

Possible Improvements:
Use a lookup table which holds up to 3 character length passwords to iterate through.
Current method involves concatenating 6 times repeating the same sequence repeatedly.
With such a large overlap in processes a lookup table would help immensely.


