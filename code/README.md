# Covert Storage Channel that exploits Protocol Field Manipulation using CTRL field in LLC [Code: CSC-PSV-LLC-CTRL]

Our covert channel implementation is on the MyCovertChannel.py. 

We have two main methods: send and receive.

send() method first creates a random binary message. The goal here is to send this message in such a way that only the reciever can decode it. This requires both sides deciding on a encode/decode method.

# The strategy
As the title says, we need to send this message using CTRL field in LLC. This field is 8 bits long, which means it can take values 0 to 255. Our covert channel 
sends the message bit by bit, that is , 0 or 1. 

Pick a limit value that acts as a separator among 256 values. If the bit value we send is 1, fill the CTRL field a number lower than limit, and vice versa. This number is picked randomly. Receiver can decode the bit, given that they know the limit value. This limit value is passed as a parameter to both sides, send and receive.

# Example

We want to send a binary message "0". First package should send the value 0 indirectly. According to our algorithm, to encode 0, the CTRL field must be one among (limit, 255]. Assume limit = 100. So the CTRL value can be anything between 100 and 255. This selection is randomized to achieve secrecy. Once we send it, receive() does the reverse and gets bit 0.
