"""Module for xmlsig-core-schema messages.

I will use xmlsec library or xmlsig library for signing and verifying the messages.
"""

# TODO: Need to check how the xmlsec and xmlsig libraries work
# I hope it will be possible to use one of them for signing and verifying the messages
# instead of implementation of xmlsig-core-schema in python
# UPDATE: It will not be possible to use xmlsec or xmlsig libraries for signing and verifying the messages
# because they are not supporting ECDSA algorithm
