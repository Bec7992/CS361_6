UTEID: ceb4343; 
FIRSTNAME: Clinton; 
LASTNAME: Bell;
CSACCOUNT: bec20;
EMAIL: ceb120411@utexas.edu; 

Makefile 'make' to run oracle.py with python3

Description:
	To solve the problem, I first learned how to correctly aquire and parse the cipher text in python. I then implemented Vaudenay algorithms in the attack() function. The attack() function solves an entire block at a time by first performing the last word oracle and then block decryption oracle on the rest of the bytes. When the result of this function is returned, it is xored with the previous cipher block in the main() function and added to the growing final message.

Feedback:
	In the end, this was a relatively simple assignment. It was cool to see the message finally pop up after I fixed my last bug (python indentation mistake, by the way. One extra tab fixed it.) The main way I could see to improve this assignment in the future is to explicitly state in the assignment write-up that the example for finding the message in the write-up is not the solution used by the paper, and that there are many different ways of performing a padding oracle attack. Other than that, is was mostly just an issue of reading the algorithm in the paper over and over again until I slightly understood what it was doing.
