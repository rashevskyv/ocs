# OCS (One Click Setup) 2.6.0 filibuster edition
![Github latest downloads](https://img.shields.io/github/downloads/rashevskyv/ocs/total.svg)

This is meant for 3ds users between firmware 9.0.0 to 11.3.0. It allows the users to go straight from stock to luma3ds with only 3 files on the sd card (if the user is using soundhax).

# Usage

<img src="https://github.com/rashevskyv/ocs/raw/master/ocs.png" alt="screenshot" height="500px">

Nothing much is needed to use this, you just need to be between firmware 9.0.0 and 11.3.0. Get soundhax `.m4a`, `otherapp.bin` and `ocs.3dsx`. Rename `ocs.3dsx` to `boot.3dsx` and put it in the root of your sd card. 

# Features

* Nothing more than 3 files are needed on your sd card.
* Installs FBI, GodMode9, Themely, Checkpoint, ftpd, lumaupdater and freeshop with keys
* Stock to luma3ds within 5 minutes.
* Inbuilt zip and 7z extractor using libarchive.
* Install tickets for eshop themes for your region
* 3dsident functions for detect system version, region and screen type 

# Building

To build ctrulib and devkitpro must be installed.
You also need to install liblzma and libarchive (you can find it in portlib folder, just copy lib and includ from there to devkitpro/libctru) from the 3ds_portlibs.

# Credits

Many thanks to Chromaryu for testing this app.

**Tinivi** for safehax.

**Yellows8** and **Smealum** for udsploit.

**Smealum** and others for ctrulib.

**Kartik** for original ocs

**joel16** for 3DSident
