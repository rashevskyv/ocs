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

u8 region = 0;

extern void progressbar(const char *string, double update, double total, bool progBarTotal);

void initServices()
{
	// acInit();
	gfxInitDefault();
	logInit();
	cfguInit();
	cfgsInit();
	ptmuInit();
	amInit();
	amAppInit();
	psInit();
	aptInit();
	hidInit();
	actInit();
	socInit((u32*)memalign(0x1000, 0x10000), 0x10000);
	fsInit();
	sdmcInit();
	
	if (isN3DS())
		osSetSpeedupEnable(true);
}

void termServices()
{
	if (isN3DS())
		osSetSpeedupEnable(false);
	
	sdmcExit();
	fsExit();
	httpcExit();
	logExit();
	gfxExit();
	socExit();
	actExit();
	hidExit();
	aptExit();
	psExit();
	acExit();
	amExit();
	ptmuExit();
	cfgsExit();
	cfguExit();
}

char * getVersion(int version)
{
	char *str_kernel = (char *)malloc(sizeof(char) * 255), *str_ver = (char *)malloc(sizeof(char) * 255), *str_sysver = (char *)malloc(sizeof(char) * 255);
	u32 os_ver = osGetKernelVersion(), firm_ver = osGetKernelVersion();
	OS_VersionBin *nver = (OS_VersionBin *)malloc(sizeof(OS_VersionBin)), *cver = (OS_VersionBin *)malloc(sizeof(OS_VersionBin));
	s32 ret;
	
	snprintf(str_kernel, 255, "%lu.%lu-%lu",
			GET_VERSION_MAJOR(os_ver),
			GET_VERSION_MINOR(os_ver),
			GET_VERSION_REVISION(os_ver)
	);
	
	snprintf(str_ver, 255, "%lu.%lu-%lu",
			GET_VERSION_MAJOR(firm_ver),
			GET_VERSION_MINOR(firm_ver),
			GET_VERSION_REVISION(firm_ver)
	);
				
	memset(nver, 0, sizeof(OS_VersionBin));
	memset(cver, 0, sizeof(OS_VersionBin));

	if (R_FAILED(ret = osGetSystemVersionData(nver, cver)))
		snprintf(str_sysver, 100, "0x%08liX", ret);
	else
		snprintf(str_sysver, 100, "%d.%d.%d-%d%c",
			cver->mainver,
			cver->minor,
			cver->build,
			nver->mainver,
			getFirmRegion()
		);
	
	if (version == 0)
		return str_kernel;
	else if (version == 1)
		return str_ver;
	else 
		return str_sysver;
}

typedef struct {
	u64 titleid;
	char name[50];
} TitleInfo;

PrintConsole top, bottom;

#define result(str,ret,steps,step_count) print("\nResult for %s:",str); \
if(ret == 0) \
{	\
	progressbar("Total Progress:", step_count, steps, true);	\
	print("\x1b[1;32m"); \
	print(" Success");	\
	printf("\n\x1b[1;37m\e[m"); \
}	\
else	\
{	\
	printf("\n\x1b[1;31m"); \
	print("\nFail: %08lX", ret); \
	printf("\n\n\x1b[1;37m\e[m"); \
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
//safeb9sinstaller
	progressbar("Total Progress:", 0, 5, true);
	print("\n\n\x1b[1;37mDownloading \e[37;42msafeb9sinstaller\e[m\n");
	Result ret = httpDownloadData(parseApi("https://api.github.com/repos/d0k3/SafeB9SInstaller/releases/latest", ".zip"));//safeb9sinstaller by d0k3
	result("Safeb9sinstaller Download", ret, 5, 1);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "SafeB9SInstaller.bin", "safehaxpayload.bin","/");
	httpFree();
	
//boot9strap
	print("\n\n\x1b[1;37mDownloading \e[37;42mboot9strap\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/SciresM/boot9strap/releases/latest",".zip"));//b9s by scrisem
	result("b9s Download", ret, 5, 2);
	mkdir("/boot9strap", 0777);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot9strap.firm", "boot9strap.firm", "/boot9strap/");
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot9strap.firm.sha", "boot9strap.firm.sha", "/boot9strap/");
	httpFree();
	
//luma
	print("\n\n\x1b[1;37mDownloading \e[37;42mluma\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/AuroraWright/Luma3DS/releases/latest", ".7z"));//luma by aurorawright
	result("Luma Download", ret, 5, 3);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "boot.firm", "boot.firm", "/");
	httpFree();
	
// luma3ds data
	print("\n\n\x1b[1;37mDownloading \e[37;42mluma3ds data\e[m\n");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/luma.zip");
	result("Download", ret, 15, 5);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	httpFree();
}

void ciaInstall(void *data, u32 size, int total, int step)
{
	Handle cia;
	Result ret = amInit();
	result("amInit", ret, total ,step);
	AM_InitializeExternalTitleDatabase(false);
	ret = AM_StartCiaInstall(MEDIATYPE_SD, &cia);
	result("Start Installing CIA", ret, total ,step);
	ret = FSFILE_Write(cia, NULL, 0, data, size, 0);
	result("Write CIA", ret, total ,step);
	ret = AM_FinishCiaInstall(cia);
	result("Finish Installing CIA", ret, total ,step);
	amExit();
}

void tikInstall(void *data, u32 size, int total, int step)
{
	Handle tik;
	Result ret = amInit();
	result("amInit", ret, total ,step);
	AM_InitializeExternalTitleDatabase(false);
	ret = AM_InstallTicketBegin(&tik);
	result("Start Installing ticket", ret, total ,step);
	ret = FSFILE_Write(tik, NULL, 0, data, size, 0);
	result("Write ticket", ret, total ,step);
	ret = AM_InstallTicketFinish(tik);
	result("Finish Installing ticket", ret, total ,step);
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
	print("\n\n\x1b[1;37mDownloading \e[37;42mhblauncher_loader\e[m\n");
	Result ret = httpDownloadData(parseApi("https://api.github.com/repos/yellows8/hblauncher_loader/releases/latest", ".zip"));//hblauncher_loader by yellows8
	result("Download", ret, 15, 1);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "hblauncher_loader.cia", "hblauncher_loader.cia", "/");
	httpFree();
	
	u32 size;
	u8 *data = fsOpenAndRead("hblauncher_loader.cia", &size);
	printf("\nTrying to install hblauncher_loader.cia\n");
	ciaInstall(data, size, 15, 1);
	remove("hblauncher_loader.cia");
	free(data);

// HBL
	print("\n\n\x1b[1;37mDownloading \e[37;42mboot.3dsx\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/fincs/new-hbmenu/releases/latest", ".3dsx"));// HBL by smealum & others
	result("Download", ret, 15, 2);
	fsOpenAndWrite("/boot.3dsx",httpRetrieveData(), httpBufSize());
	httpFree();
	
// FBI
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mFBI\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/steveice10/FBI/releases/latest", ".cia"));//FBI by steveice10
	result("Download", ret, 15, 3);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 3);
	httpFree();
	
// lumaupdater
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mlumaupdater\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/KunoichiZ/lumaupdate/releases/latest", ".cia")); //lumaupdater by hamcha & KunoichiZ
	result("Download", ret, 15, 4);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 4);
	httpFree();
	
// luma3ds data
	print("\n\n\x1b[1;37mDownloading \e[37;42mluma3ds data\e[m\n");
	remove("/luma/config.bin");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/luma.zip");
	result("Download", ret, 15, 5);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	httpFree();
	
// godmode9 and sripts
	print("\n\n\x1b[1;37mDownloading \e[37;42mgodmode9\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/d0k3/GodMode9/releases/latest", ".zip"));// godmode9 by d0k3
	result("Download", ret, 15, 6);
	mkdir("/luma/payloads", 0777);
	mkdir("/gm9",0777);
	mkdir("/gm9/scripts", 0777);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "GodMode9.firm", "GodMode9.firm", "/luma/payloads/"); 
	
	print("\n\n\x1b[1;37mDownloading \e[37;42mgodmode9 sd card cleaup script\e[m\n");
	ret = httpDownloadData("https://raw.githubusercontent.com/rashevskyv/3ds/master/gm9_scripts/cleanup_sd_card.gm9"); //cleanup_sd_card.gm9 by d0k3
	result("Download", ret, 15, 7);
	fsOpenAndWrite("/gm9/scripts/cleanup_sd_card.gm9", httpRetrieveData(), httpBufSize());
	
	print("\n\n\x1b[1;37mDownloading \e[37;42mgodmode9 ctr-nand luma script\e[m\n");
	ret = httpDownloadData("https://raw.githubusercontent.com/rashevskyv/3ds/master/gm9_scripts/setup_ctrnand_luma3ds.gm9"); //setup_ctrnand_luma3ds by d0k3
	result("Download", ret, 15, 8);
	fsOpenAndWrite("/gm9/scripts/setup_ctrnand_luma3ds.gm9", httpRetrieveData(), httpBufSize());
	
	print("\n\n\x1b[1;37mDownloading \e[37;42mBackup_SysNAND script\e[m\n");
	ret = httpDownloadData("https://raw.githubusercontent.com/rashevskyv/3ds/master/gm9_scripts/Backup_SysNAND.gm9"); //setup_ctrnand_luma3ds by d0k3
	result("Download", ret, 15, 8);
	fsOpenAndWrite("/gm9/scripts/Backup_SysNAND.gm9", httpRetrieveData(), httpBufSize());

/*
// OCS
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mOCS\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/rashevskyv/ocs/releases/latest", ".3dsx"));//OCS
	result("Download", ret, 15, 9);
	mkdir("/3ds",0777);
	fsOpenAndWrite("/3ds/ocs.3dsx", httpRetrieveData(), httpBufSize());
	httpFree();
*/

// ftpd
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mftpd\e[m\n");
	ret = httpDownloadData("https://mtheall.com/~mtheall/ftpd.cia"); //ftpd by mtheall
	result("Download", ret, 15, 9);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 9);
	httpFree();

// LumaLocaleSwitcher
CFGU_SecureInfoGetRegion(&region);
	if (region != 2) {

		print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mLumaLocaleSwitcher\e[m\n");
		Result ret = httpDownloadData(parseApi("https://api.github.com/repos/Possum/LumaLocaleSwitcher/releases/latest", "NIGHTLY.cia"));//LumaLocaleSwitcher by Possum
		result("Download", ret, 15, 10);
		ciaInstall(httpRetrieveData(), httpBufSize(), 15, 10);
		httpFree();
		}

// Checkpoint
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mCheckpoint\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/BernardoGiordano/Checkpoint/releases/latest", ".cia"));//Checkpoint by BernardoGiordano
	result("Download", ret, 15, 11);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 11);
	httpFree();
	
// Themely
	print("\n\n\x1b[1;37mDownloading and Installing \e[37;42mThemely\e[m\n");
	ret = httpDownloadData(parseApi("https://api.github.com/repos/ErmanSayin/Themely/releases/latest", ".cia"));//Themely by ErmanSayin
	result("Download", ret, 15, 12);
	ciaInstall(httpRetrieveData(), httpBufSize(), 15, 12);
	httpFree();

// freeshop
	print("\n\n\x1b[1;37mDownloading \e[37;42mfreeshop\e[m\n");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/freeshop.zip");
	result("Download", ret, 15, 13);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "freeshop.cia", "freeshop.cia", "/");
	httpFree();
	data = fsOpenAndRead("freeshop.cia", &size);
	printf("\nTrying to install freeshop\n");
	ciaInstall(data, size, 15, 13);
	remove("freeshop.cia");
	free(data);
	
// freeshop data
	print("\n\n\x1b[1;37mDownloading \e[37;42mfreeshop data\e[m\n");
	ret = httpDownloadData("https://github.com/rashevskyv/3ds/raw/master/files/freeShop_data.zip");
	result("Download", ret, 15, 14);
	archiveExtractFile(httpRetrieveData(), httpBufSize(), "__ALL__", "__NOTUSED__", "__NOTUSED__");
	httpFree();

//installing tickets for menu themes
	CFGU_SecureInfoGetRegion(&region);
	print("\n\n\x1b[1;37mDownloading \e[37;42mtickets\e[m\n");
	if (region == 2) {
	// EUR tickets
		print("\n\n\x1b[1;37mDownloading \e[37;42mtickets for EUR themes\e[m\n");
		Result ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00009800");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();
		
		ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00009801");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();

		ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00009802");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();

		ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00009803");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();
	}
	else if (region == 1) {
	// USA tickets
		print("\n\n\x1b[1;37mDownloading \e[37;42mtickets for USA themes\e[m\n");
		Result ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00008f01");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();
	}
	else if (region == 0) {
	// JAP tickets
		print("\n\n\x1b[1;37mDownloading \e[37;42mtickets for JAP themes\e[m\n");
		Result ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00008201");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();
		
		ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00008202");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();

		ret = httpDownloadData("http://3ds.titlekeys.gq/ticket/0004008c00008203");
		result("Download", ret, 15, 15);
		tikInstall(httpRetrieveData(), httpBufSize(), 15, 15);
		httpFree();
	}
	else {
		printf("skip installing tickets");
	}
}

int main()
{
	
	//preliminary stuff
	
	char * vers="2.6.0";

	initServices();
	
	consoleInit(GFX_TOP, &top);
	consoleInit(GFX_BOTTOM, &bottom);
	
	consoleSelect(&bottom);
	printf("\n\x1b[1;37m");
	printf("\nWelcome to OCS for pirates!!!\nv%s\n\nMade by: \x1b[1;32mKartik\x1b[1;37m\nModified by: \x1b[1;32mxHR\x1b[1;37m\nfor\x1b[1;33m http://vk.com/3ds_cfw\x1b[1;37m\n\nSpecial Thanks to :\x1b[1;33m\nChromaryu\x1b[1;37m for testing\n\x1b[1;35mSmealum\x1b[1;37m and \x1b[1;33myellows8\x1b[1;37m for udsploit\n\x1b[1;36mTinivi\x1b[1;37m for safehax", vers);
	consoleSelect(&top);
	printf("\n\x1b[1;37m");
	bool cfwflag = false;
	
	printf("\x1b[33;1m*\x1b[0m System version: \x1b[33;1m%s\n", getVersion(2));
	
	printf("\x1b[33;1m*\x1b[0m System region: \x1b[33;1m%s\n", getRegion());
		
	printf("\x1b[31;1m*\x1b[0m Screen type: \x1b[31;1m %s \n\x1b[0m", getScreenType());
	
	printf("\x1b[1;37m\n\n\n\--------------------------------------------------\n                 Press \x1b[1;32mA\x1b[1;37m to begin\n\n--------------------------------------------------\n\n\n");
	
	while(aptMainLoop())
		{
			hidScanInput();

			if(hidKeysDown() & KEY_A)
				break;

		}
	consoleClear();
	consoleSelect(&bottom);
	consoleClear();
	printf("\n\x1b[1;37m");
	printf("\nWelcome to OCS for pirates!!!\nv %s\n\nMade by: \x1b[1;32mKartik\x1b[1;37m\nModified by: \x1b[1;32mxHR\x1b[1;37m\nfor\x1b[1;33m http://vk.com/3ds_cfw\x1b[1;37m", vers);
	consoleSelect(&top);
	printf("\nChecking if cfw is installed\n");
	Result ret = checkRunningCFW();
	(ret == 0xF8C007F4) ? (cfwflag = false) : (cfwflag = true);
	consoleSelect(&top);
	httpcInit(0);
	if(cfwflag == false)
	{
		printf("\nx1b[1;31mNot running cfw\x1b[1;37m\e[m\n");
		if(checkFileExists("/safehaxpayload.bin") == 0) //check if files already exsist for step 1.
		{	
			print("\n\n\x1b[1;37mDownloading files for CFW installation\n");
			downloadExtractStep1();
		}	
		printf("\nRunning exploits\n");
		doExploitsStep1();
	}

	else
	{
		//User is running luma cfw
		printf("\n\x1b[1;32mYou running CFW\n\x1b[1;37m");
		print("\n\n\n\x1b[1;37mDownloading files\n\n");
		downloadExtractStep2();
		//consoleClear();
		printf("\x1b[1;37m\n\n\n\--------------------------------------------------\n                Proccess Finished.\n\n--------------------------------------------------\n\n\n               Press \x1b[1;32mStart\x1b[1;37m to exit.\n\n     Console will boot to \x1b[1;32mHomebrew Launcher\x1b[1;37m.\n   In HBL press \x1b[1;32m(HOME)\x1b[1;37m for return to menu Home.\n\n\n");
	}
	end:
		while(aptMainLoop())
		{
			hidScanInput();

			if(hidKeysDown() & KEY_START)
				break;

		}

	termServices();

}
