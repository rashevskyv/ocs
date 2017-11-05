#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <3ds.h>
#include <fcntl.h>
#include "kernel.h"
#include "asm.h"
#include "exploits.h"
#include "archive.h"
#include "log.h"
#include "httpc.h"
#include "fs.h"
#include "jsmn.h"

extern void progressbar(const char *string, double update, double total, bool progBarTotal);


PrintConsole top, bottom;

#define result(str,ret,steps,step_count) print("\nResult for %s:",str); \
if(ret == 0) \
{	\
	progressbar("Total Progress:", step_count, steps, true);	\
	printf("\n\x1b[1;32m"); \
	print("\nSuccess\n");	\
	printf("\n\x1b[1;37m"); \
}	\
else	\
{	\
	printf("\n\x1b[1;31m"); \
	print("\nFail: %08lX", ret); \
	printf("\n\n\x1b[1;37m"); \
}	

//Code from jsmn example
int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
		strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

char *parseApi(const char *url, const char *format)
{
	printf("\nParsing JSON to get latest release\n");
	Result ret = httpDownloadData(url);
	jsmn_parser p = {};
	jsmn_init(&p);
	static char downloadUrl[0x100], returnDownloadUrl[0x100];
	jsmntok_t t[512] = {};
	u8* apiReqData = httpRetrieveData();
	int r = jsmn_parse(&p, (const char *)apiReqData, httpBufSize(), t, sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("\nFailed to parse JSON %d", r);
	}
	bool inassets = false;
	for (int i = 0; i < r; i++) {
		if (!inassets && jsoneq((const char*)apiReqData, &t[i], "assets") == 0) {
			inassets = true;
		}
		if (inassets) {
			if (jsoneq((const char*)apiReqData, &t[i], "browser_download_url") == 0) {
				sprintf(downloadUrl, "%.*s", t[i+1].end-t[i+1].start, apiReqData + t[i+1].start);
				if(strstr(downloadUrl, format) != NULL)
				{
					strcpy(returnDownloadUrl, downloadUrl);
					printf("\nDownloading the latest release\n");
				}		
			}
		}
	}
	httpFree();
	return returnDownloadUrl;
}

void downloadExtractStep1()
{
	progressbar("Total Progress:", 0, 5, true);
	print("\nDownloading safeb9sinstaller\n");
	Result ret = httpDownloadData(parseApi("https://api.github.com/repos/d0k3/SafeB9SInstaller/releases/latest", ".zip"));//safeb9sinstaller by d0k3
	result("Safeb9sinstaller Download", ret, 5, 1);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "SafeB9SInstaller.bin", "safehaxpayload.bin","/");
	httpFree();
	print("\nDownloading boot9strap\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/SciresM/boot9strap/releases/latest",".zip"));//b9s by scrisem
	result("b9s Download", ret, 5, 2);
	mkdir("/boot9strap",0777);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot9strap.firm", "boot9strap.firm", "/boot9strap/");
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot9strap.firm.sha", "boot9strap.firm.sha", "/boot9strap/");
	httpFree();
	print("\nDownloading luma\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/AuroraWright/Luma3DS/releases/latest", ".7z"));//luma by aurorawright
	result("Luma Download", ret, 5, 3);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot.firm", "boot.firm", "/");
	httpFree();
}

void ciaInstall(void *data, u32 size, int total, int step)
{
	Handle cia;
	Result ret = amInit();
	result("amInit", ret, total ,step);
	AM_InitializeExternalTitleDatabase(false);
	ret = AM_StartCiaInstall(MEDIATYPE_SD, &cia);
	result("Start_CiaInstall", ret, total ,step);
	ret = FSFILE_Write(cia, NULL, 0, data, size, 0);
	result("CIA write", ret, total ,step);
	ret = AM_FinishCiaInstall(cia);
	result("Finish Cia Install", ret, total ,step);
	amExit();
}

void doExploitsStep1()
{
	Result ret = 1;
	while(ret > 0)
	{
		ret = udsploit();
		result("Udsploit", ret, 5, 4);
		if(ret == 0)
			ret = hook_kernel();
		result("hook_kernel", ret, 5, 5);
	}
	safehax();
}

void downloadExtractStep2()
{	
	progressbar("Total Progress:", 0, 15, true);

// hblauncher_loader
	// Best time to install hblauncher_loader
	print("\nDownloading \e[37;42mhblauncher_loader\e[m\n");
	Result ret = httpDownloadData(parseApi("https://api.github.com/repos/yellows8/hblauncher_loader/releases/latest", ".zip"));//hblauncher_loader by yellows8
	result("Download", ret, 15, 1);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "hblauncher_loader.cia", "hblauncher_loader.cia", "/");
	httpFree();
	
	u32 size;
	u8 *data = fsOpenAndRead("hblauncher_loader.cia", &size);
	printf("\nTrying to install hblauncher_loader.cia\n");
	ciaInstall(data, size, 15, 1);
	free(data);

// HBL
	print("\nDownloading \e[37;42mboot.3dsx\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/fincs/new-hbmenu/releases/latest", ".3dsx"));// HBL by smealum & others
	result("Download", ret, 15, 2);
	fsOpenAndWrite("/boot.3dsx",httpRetrieveData(), httpBufSize());
	httpFree();
	
// FBI
	print("\nDownloading and Installing \e[37;42mFBI\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/steveice10/FBI/releases/latest", ".cia"));//FBI by steveice10
	result("Download", ret, 15, 3);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 3);
	httpFree();
	
// lumaupdater
	print("\nDownloading and Installing \e[37;42mlumaupdater\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/KunoichiZ/lumaupdate/releases/latest", ".cia")); //lumaupdater by hamcha & KunoichiZ
	result("Download", ret, 15, 4);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 4);
	httpFree();
	
// luma3ds data
	print("\nDownloading \e[37;42mluma3ds data\e[m\n");
	remove("/luma/config.bin");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/luma.zip");
	result("Download", ret, 15, 5);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	httpFree();
	
// godmode9 and sripts
	print("\nDownloading \e[37;42mgodmode9\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/d0k3/GodMode9/releases/latest", ".zip"));// godmode9 by d0k3
	result("Download", ret, 15, 6);
	mkdir("/luma/payloads", 0777);
	mkdir("/gm9",0777);
	mkdir("/gm9/scripts", 0777);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "GodMode9.firm", "GodMode9.firm", "/luma/payloads/"); 
	
	print("\nDownloading \e[37;42mgodmode9 sd card cleaup script\e[m\n");
	ret = httpDownloadData("http://3ds.guide/gm9_scripts/cleanup_sd_card.gm9"); //cleanup_sd_card.gm9 by d0k3
	result("Download", ret, 15, 7);
	fsOpenAndWrite("/gm9/scripts/cleanup_sd_card.gm9", httpRetrieveData(), httpBufSize());
	
	print("\nDownloading godmode9 ctr-nand luma script\n");
	ret = httpDownloadData("http://3ds.guide/gm9_scripts/setup_ctrnand_luma3ds.gm9"); //setup_ctrnand_luma3ds by d0k3
	result("Download", ret, 15, 8);
	fsOpenAndWrite("/gm9/scripts/setup_ctrnand_luma3ds.gm9", httpRetrieveData(), httpBufSize());
	
// 3DSident
	print("\nDownloading and Installing \e[37;42m3DSident\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/joel16/3DSident/releases/latest", "3DSident.cia"));//3DSident by joel16
	result("Download", ret, 15, 9);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 9);
	httpFree();
	
// Checkpoint
	print("\nDownloading and Installing \e[37;42mCheckpoint\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/BernardoGiordano/Checkpoint/releases/latest", ".cia"));//Checkpoint by BernardoGiordano
	result("Download", ret, 15, 10);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 11);
	httpFree();
	
// Themely
	print("\nDownloading and Installing \e[37;42mThemely\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/ErmanSayin/Themely/releases/latest", ".cia"));//Themely by ErmanSayin
	result("Download", ret, 15, 12);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 12);
	httpFree();
	
// freeshop
	print("\nDownloading \e[37;42mfreeshop\e[m\n");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/freeshop.zip");
	result("Download", ret, 15, 13);
	mkdir("/cias", 0777);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "freeshop.cia", "freeshop.cia", "/cias/");
	httpFree();
	data = fsOpenAndRead("/cias/freeshop.cia", &size);
	printf("\nTrying to install freeshop\n");
	ciaInstall(data, size, 15, 14);
	free(data);

// freeshop data
	print("\nDownloading \e[37;42mfreeshop data\e[m\n");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/freeShop_data.zip");
	result("Download", ret, 15, 15);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	httpFree();
					
}

int main()
{
	//preliminary stuff
	gfxInitDefault();
	logInit();
	consoleInit(GFX_TOP, &top);
	consoleInit(GFX_BOTTOM, &bottom);
	consoleSelect(&bottom);
	printf("\n\x1b[1;37m");
	printf("\nWelcome to \x1b[1mOCS!!\x1b[0m\nMade by:- \x1b[1;32mKartik\x1b[1;37m\nSpecial Thanks to :-\n\x1b[1;33mChromaryu\x1b[1;37m:- For Testing\n\x1b[1;35mSmealum\x1b[1;37m and \x1b[1;33myellows8\x1b[1;37m:- For udsploit\n\x1b[1;36mTinivi\x1b[1;37m for safehax");
	consoleSelect(&top);
	printf("\n\x1b[1;37m");
	bool cfwflag = false;
	acWaitInternetConnection();
	printf("\nPress A to begin\n");
	while(aptMainLoop())
		{
			hidScanInput();

			if(hidKeysDown() & KEY_A)
				break;

		}
	printf("\nChecking if cfw is installed\n");
	Result ret = checkRunningCFW();
	(ret == 0xF8C007F4) ? (cfwflag = false) : (cfwflag = true);
	consoleSelect(&top);
	httpcInit(0);
	if(cfwflag == false)
	{
		printf("\nNot running cfw\n");
		if(checkFileExists("/safehaxpayload.bin") == 0) //check if files already exsist for step 1.
		{	
			print("\nDownloading files for CFW installation\n");
			downloadExtractStep1();
		}	
		printf("\nRunning exploits\n");
		doExploitsStep1();
	}
	else
	{
		//User is running luma cfw
		printf("\n\x1b[1;32mYou running CFW\n\x1b[1;37m");
		print("\n\nDownloading files\n\n");
		//parseApi("https://api.github.com/repos/pirater12/ocs/releases/latest");
		downloadExtractStep2();
		printf("\nProccess Finished. Press Start to exit and enjoy\n");
	}
	end:
		while(aptMainLoop())
		{
			hidScanInput();

			if(hidKeysDown() & KEY_START)
				break;

		}
	httpcExit();
	logExit();
	gfxExit();
		
}
