# Open ZRTP

Open ZRTP is a cryptographic key-agreement protocol to negotiate the keys for encryption between two end points in a Voice over Internet Protocol (VoIP) phone telephony call based on the Real-time Transport Protocol. It uses Diffie-Hellman key exchange and the Secure Real-time Transport Protocol (SRTP) for encryption.

Open ZRTP is a cross platform project written in C++. Our testing has shown that it compiles quickly and easily on Win32/64, Mac OS X and many Linux distros.

ZRTP was originally created by Phil Zimmermann, the creator of PGP but his ZRTP libraries are licensed under GPL which means you can't use his libraries in a commercial project without paying or open sourcing your entire product.

As of this writing, Open ZRTP is the only open source zrtp implementation that is released under a LGPL license. The entire project was built by following the IETF specs found at http://tools.ietf.org/html/draft-zimmermann-avt-zrtp

If you intend to implement Open ZRTP in your project, please let us know and please submit any bugs or improvements that you might make.
