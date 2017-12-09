# OCS (One Click Setup) 2.6.0 filibuster edition
![Github latest downloads](https://img.shields.io/github/downloads/rashevskyv/ocs/total.svg)

Пользователи с прошивкой между 9.0.0 и 11.3.0 с помощью этой программы могут очень легко и просто взломать консоль, буквально за пару кликов. 

This is meant for 3ds users between firmware 9.0.0 to 11.3.0. It allows the users to go straight from stock to luma3ds with only 3 files on the sd card (if the user is using soundhax).

# Usage

<img src="https://github.com/rashevskyv/ocs/raw/master/ocs.png" alt="screenshot" height="500px">

Используйте в паре с саундхакс на прошивках между 9.0.0 и 11.3.0 для взлома и установки дополнительного софта, либо используйте уже на взломаной консоли только для установки софта.

Положите в корень карты памяти `.m4a` от soundhax, `otherapp.bin` пейлоадер от smealum и `boot.3dsx` из этого репозитория. 

Use it with soundhax between firmware 9.0.0 to 11.3.0 for hacking your console and install all additional software. Or use it on CFW for install only. 
Get soundhax `.m4a`, `otherapp.bin` and `ocs.3dsx`. Rename `ocs.3dsx` to `boot.3dsx` and put it in the root of your sd card. 

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
