# Side Channel Timing Attack Analysis in Authentication Methods

**TL;DR** "use secure hashing methods that time buffer their return output rather than rolling-your-own method, let alone doing direct password/token string comparison"

### Why did I do this?
What drove this notebook was Microsoft's discovery of vulnerabilities in NetGear's DGN-2200v1 series routers, including finding that the routers store plaintext credentials and  use the C strcmp method to validate passwords.  A client was trying to understand why strcmp could leak information about passwords, so I created this notebook. I'm calling this "a hash comparison appreciation exercise".


If you aren't familiar with the problem - this is a weird implementation. Stored credentials in plaintext on the system is never a good idea. This is compounded by using the String Comparison (strcmp) method to determine if the password is correct which induces this flaw. 

The gold standard for auth comparison is to: 
- use a hashing method to manage the creds creation and validation.
- On account creation only store the hashed value (preferably with a salt), never store the original string
- On user validation hash the incoming password then compare the hashes to determine if the credential is correct.


The issue, described by Microsoft's 365 Defender Research Team on June 30, 2021:  
https://www.microsoft.com/security/blog/2021/06/30/microsoft-finds-new-netgear-firmware-vulnerabilities-that-could-lead-to-identity-theft-and-full-system-compromise/


```
Deriving saved router credentials via a cryptographic side-channel

At this stage, we already had complete control over the router, but we continued investigating how the authentication itself was implemented.

If a page had to be authenticated, HTTPd would require HTTP basic authentication. The username and password would be encoded as a base64 string (delimited by a colon), sent in the HTTP header, and finally verified against the saved username and password in the router’s memory. The router stores this information (along with the majority of its configuration) in NVRAM, that is, outside the filesystem that we had extracted.

However, when we examined the authentication itself, we discovered a side-channel attack that can let an attacker get the right credentials:

Note that the username and the password are compared using strcmp. The libc implementation of strcmp works by comparing character-by-character until a NUL terminator is observed or until a mismatch happens.
```


## Demonstrating the side-channel Timing Attack analysis against authentication methods that use strcmp

Why authentication shouldn't use libc strcmp (or other non-time-compensated methods). 

The basic idea is to show that, when you make lots of tries to a system, analyzing the amount of time each transaction takes to return can reveal meaningful information about a secret string used in a password or token.

We'll be using python code to demonstrate the action and analysis, but this can be performed with any language that uses similar methods.


### The Breakdown
Our secret string is 'apple'.

A client presents the secret string to the server, who knows the secret string, in an operation that will fail if the secret is incorrect.

So:

Client -> 'apple' -> Server

Server:

1.    receives the credentials from the client containing the string.
2.    gets the local copy of the secret
3.    strcmp's the raw string of the client credential to the local secret
      - compare each byte from l to r
      - when a byte fails, return False
      - if the byte matches move to next char
      - Return True if nothing fails or return False when a match fails. 
4.    Server -> True/False -> Client

The problem is that for every correct chunk of text on the LHS the "fail" takes longer to return. Also - longer strings also take longer to return.

So "b" or "broken" returns a failure instantly, but "a", "aplomb", "app", "application", etc will each take slightly longer for each character matched. The times are tiny, but it's possible to model the jitter window such that these lengths don't get lost in the noise. This can drastically cut down the time of a brute force attack and enhance its chances of success.

**using sound hash functions or tools (like bcrypt) which return in a constant time and not rolling-your-own solves this problem.**

### Why?

A few reasons:
- if you store a hash, then both strings are always the same size. 
- the mature methods also add time-based buffers into place so that long/short/alphabetically diverse strings all return in constant time. No predictable time variation = no attack.
- modern mathods/tools for passwords also include strengtheners like salts. Not available for token comparison.

This is where I get in over my head. Smarter People Than I assure me that the way to do this capital-S Securely has a number of small, difficult problems. 

I don't think it's a waste of time for a developer to want to expand their technique on the company dime, but naive solutions in this arena are a big deal. To limit potential impact to your project or your employer/shareholders, you probably want to partner with someone who writes secure services as you approach mastery. Otherwise you risk turning your project or employer into a CERT advisory.






