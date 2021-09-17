# Timing Attack Analysis 

TL;DR - use secure hashcmp methods that time buffer their return output rather than rolling-your-own, or doing direct password/token/comparison.


## Demonstrating Timing Attack analysis against authentication methods that use strcmp

This is a quick demonstration of how authentication shouldn't use strcmp (or other non-time-compensated methods) 


The idea is to show that time analysis can reveal meaningful information about a string used in a secret or a password if the amount of time it takes to perform the string match isn't buffered.

This example will be to show how the libc strcmp method reveals information about a secret string and, possibly, the string itself in a brute force attack. We'll be using python code to demonstrate the action and analysis, but this can be performed with any language that uses similar methods.

Our secret string is 'apple'.

A client presents the secret string to the server, who knows the secret string, in an operation that will fail if the secret is incorrect.

So:

Client -> 'apple' -> Server

Server:

    receives a buffer containing the string.
    gets a copy of the secret
    strcmp's the two strings
        analyze bytes from l to r
        when a byte fails, return False
        if no bytes fail move to next char.
        Return True if nothing fails or False when a match fails. Server ->True/False -> Client

The problem is that for every correct chunk of text on the LHS the "fail" takes longer to return. Also - longer strings also take longer to return.

So "b" or "broken" returns a failure instantly, but "a", "aplomb", "app", "application", etc will each take slightly longer for each character matched. The times are tiny, but it's possible to model the jitter window such that these lengths don't get lost in the noise. This can drastically cut down the time of a brute force attack and enhance its chances of success.

**using sound hash functions which return in a constant time and not rolling-your-own solves this problem.**

Also: for authentication purposes it's an antipattern to store the secret plaintext or decode an encrypted secret to compare in plaintext. Hashing the secret, storing the hash then comparing the hashes also obscures the size of your secret by making the compared strings the same lengh, and increasing the problem for a brute force attack.



