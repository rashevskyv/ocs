#include <stdio.h>
#include <stdlib.h>
#include <3ds.h>
#include <stdarg.h>
#include <dirent.h>
#include <math.h>


#include "lodepng.h"
#include "actu.h"
#include "ext.h"
#include "ConvertUTF.h"

int print2(char *format, ...)
{
    va_list args;
    va_start(args, format);
	int ret = vprintf(format, args);
    va_end(args);
	gfxFlushBuffers();
	gfxSwapBuffers();
	return ret;
}

void drawPixel(u8* framebuffer, int x, int y, int r, int g, int b) {

	if (x > 0 && x < 400 && y > 0 && y < 240) {
		int index = 3*((239-y)+x*240);
		framebuffer[index] = b;
		framebuffer[index+1] = g;
		framebuffer[index+2] = r;
	}
}

int pngToRGB565(char* filename, u16* rgb_buf_64x64, u8* alpha_buf_64x64, u16* rgb_buf_32x32, u8* alpha_buf_32x32) {

	int ret = 0;
	u8* image;
	unsigned width, height;
	
	ret = lodepng_decode32_file(&image, &width, &height, filename);
	if (ret) {print2("error %u: %s\n", ret, lodepng_error_text(ret)); return 0;}
	
	if (width < 64 || height < 64 || width % 64 != 0 || width % 64 != 0 || width > 12*384  || height > 6*384) {
		print2("Wrong image size, should be 64x64 or a multiple thereof (maximum 768x384). \n");
		ret = 0;
		goto end;
	}
	
	print2("success!\n");
	
	int x, y, r, g, b, a;
	
	int rand_x = rand() % (400-width);
	int rand_y = rand() % (240-height);
	
	memset(alpha_buf_64x64, 0, 12*6*64*64/2);
	memset(alpha_buf_32x32, 0, 12*6*32*32/2);
	
	u8* framebuffer = gfxGetFramebuffer(GFX_TOP, GFX_LEFT, NULL, NULL);
	
	for (y=0; y < height; ++y) {
		for (x=0; x < width; ++x) {
			r = image[y*width*4 + x*4 + 0] >> 3;
			g = image[y*width*4 + x*4 + 1] >> 2;
			b = image[y*width*4 + x*4 + 2] >> 3;
			a = image[y*width*4 + x*4 + 3] >> 4;
			
			int rgb565_index = 8*64*((y/8)%8) | 64*((x/8)%8) | 32*((y/4)%2) | 16*((x/4)%2) | 8*((y/2)%2) | 4*((x/2)%2) | 2*(y%2) | (x%2);
			
			//only applicable when more than one badge being created from image
			rgb565_index |= 64*64*(height/64)*(x/64) + 64*64*(y/64);
			
			rgb_buf_64x64[rgb565_index] = (r << 11) | (g << 5) | b;
			alpha_buf_64x64[rgb565_index / 2] |= a << (4*(x%2));
			
			if (a) drawPixel(framebuffer, rand_x+x, rand_y+y, image[y*width*4 + x*4], image[y*width*4 + x*4 + 1], image[y*width*4 + x*4 + 2]);
		}
	}

	for (y=0; y < height; y+=2){
		for (x=0; x < width; x+=2){
			r = (image[y*width*4 + x*4 + 0] + image[(y+1)*width*4 + x*4 + 0] + image[y*width*4 + (x+1)*4 + 0] + image[(y+1)*width*4 + (x+1)*4 + 0]) >> 5;
			g = (image[y*width*4 + x*4 + 1] + image[(y+1)*width*4 + x*4 + 1] + image[y*width*4 + (x+1)*4 + 1] + image[(y+1)*width*4 + (x+1)*4 + 1]) >> 4;
			b = (image[y*width*4 + x*4 + 2] + image[(y+1)*width*4 + x*4 + 2] + image[y*width*4 + (x+1)*4 + 2] + image[(y+1)*width*4 + (x+1)*4 + 2]) >> 5;
			a = (image[y*width*4 + x*4 + 3] + image[(y+1)*width*4 + x*4 + 3] + image[y*width*4 + (x+1)*4 + 3] + image[(y+1)*width*4 + (x+1)*4 + 3]) >> 6;
			
			int halfx = x/2;
			int halfy = y/2;
			
			int rgb565_index = 4*64*((halfy/8)%4) | 64*((halfx/8)%4) | 32*((halfy/4)%2) | 16*((halfx/4)%2) | 8*((halfy/2)%2) | 4*((halfx/2)%2) | 2*(halfy%2) | (halfx%2);
			
			rgb565_index |= 32*32*(height/64)*(x/64) + 32*32*(y/64);
			
			rgb_buf_32x32[rgb565_index] = (r << 11) | (g << 5) | b;
			alpha_buf_32x32[rgb565_index / 2] |= a << (4*(halfx%2));
		}
	}
	
	ret = (height/64)*(width/64); //number of badges in buffer
	
	end:
	free(image);
	return ret;
}

int rgb565ToPng(char* filename, u16* rgb_buf, u8* alpha_buf) {

	u8* image = malloc(64*64*4);
	if (!image) return -1;
	
	int i, x, y, r, g, b, a;
	
	for (i=0; i < 64*64; ++i) {
	
		r = (rgb_buf[i] & 0xF800) >> 11;
		g = (rgb_buf[i] & 0x07E0) >> 5;
		b = (rgb_buf[i] & 0x001F);
		a = (alpha_buf[i/2] >> (4*(i%2))) & 0x0F;
		
		r = round(r * 255.0 / 31.0);
		g = round(g * 255.0 / 63.0);
		b = round(b * 255.0 / 31.0);
		a = a * 0x11;
		
		x = 8*((i/64)%8) + (((i%64)&0x01) >> 0) + (((i%64)&0x04) >> 1) + (((i%64)&0x10) >> 2);
		y = 8*(i/512) + (((i%64)&0x02) >> 1) + (((i%64)&0x08) >> 2) + (((i%64)&0x20) >> 3);
		
		image[y*64*4 + x*4 + 0] = r;
		image[y*64*4 + x*4 + 1] = g;
		image[y*64*4 + x*4 + 2] = b;
		image[y*64*4 + x*4 + 3] = a;
	}
	
	Result ret = lodepng_encode32_file(filename, image, 64, 64);
	if (ret) print2("error %u: %s\n", ret, lodepng_error_text(ret));
	
	free(image);
	return ret;
}

int setupExtdata() {

	u32 extdata_archive_lowpathdata[3] = {mediatype_SDMC, 0x000014d1, 0};
	FS_archive extdata_archive = (FS_archive){ARCH_EXTDATA, (FS_path){PATH_BINARY, 0xC, (u8*)extdata_archive_lowpathdata}};
	
	Result ret = FSUSER_OpenArchive(NULL, &extdata_archive);
	FSUSER_CloseArchive(NULL, &extdata_archive);
	
	if (ret==0) {
		print2("Extdata exists.\n");
		return 0;
		
	} else {
	
		print2("Creating ExtSaveData...\n");
		ret = CreateExtSaveData(0x14d1);
		if (ret) print2("CreateExtSaveData failed! %08x\n", ret);
		return ret;
	}
}

u64 getShortcut(char *filename) {

	u64 shortcut = 0xFFFFFFFFFFFFFFFF;
	
	char *p1;
	for (p1=filename; *p1 != '.' && *p1 != '\0'; ++p1) {;}
	
	if (*p1 != '.') return shortcut;
	++p1;
	
	char *p2;
	for (p2=p1; *p2 != '.' && *p2 != '\0'; ++p2) {;}
	
	if (*p2 != '.') return shortcut;
	if (p2-p1 != 8) return shortcut;
	
	unsigned int lowpath;
	
	if (sscanf(p1, "%08x", &lowpath) != 1) return shortcut;
	
	shortcut = 0x0004001000000000 + lowpath;
	return shortcut;
}

int compareStrings(const void* a, const void* b ) {
	return strcmp(a, b);
}

void removeInvalidChars(char *str){

	char *p;
	for (p=str; *p != '\0'; ++p) {
		if (*p == '.' || (*p > 0 && *p < 0x20) || *p == ':') {
			*p = ' ';
		}
	}
}

int dumpPrexistingBadges() {

	u32 extdata_archive_lowpathdata[3] = {mediatype_SDMC, 0x000014d1, 0};
	FS_archive extdata_archive = (FS_archive){ARCH_EXTDATA, (FS_path){PATH_BINARY, 0xC, (u8*)extdata_archive_lowpathdata}};
	FS_path badgeDataPath = FS_makePath(PATH_CHAR, "/BadgeData.dat");
	FS_path badgeMngPath = FS_makePath(PATH_CHAR, "/BadgeMngFile.dat");
	
	int ret = 0;
	u32 bytesRead;
	u64 badgeDataSize = 0xF4DF80;
	u64 badgeMngSize = 0xD4A8;
	
	u8 *badgeDataBuffer = NULL;
	u8 *badgeMngBuffer = NULL;
	Handle filehandle;
	
	badgeDataBuffer = malloc(badgeDataSize);
	if (badgeDataBuffer == NULL) {print2("Out of memory!\n"); ret = -2; goto end;}
	memset(badgeDataBuffer, 0, badgeDataSize);
	
	badgeMngBuffer = malloc(badgeMngSize);
	if (badgeMngBuffer == NULL) {print2("Out of memory!\n"); ret = -3; goto end;}
	memset(badgeMngBuffer, 0, badgeMngSize);
	
	
	ret = FSUSER_OpenArchive(NULL, &extdata_archive);
	if (ret) goto end;
	
	ret = FSUSER_OpenFile(NULL, &filehandle, extdata_archive, badgeDataPath, FS_OPEN_READ, 0);
	if (ret) goto end;
	ret = FSFILE_Read(filehandle, &bytesRead, 0, badgeDataBuffer, badgeDataSize);
	if (ret) goto end;
	FSFILE_Close(filehandle);
	
	if (bytesRead != badgeDataSize) {ret = -4; goto end;}
	
	ret = FSUSER_OpenFile(NULL, &filehandle, extdata_archive, badgeMngPath, FS_OPEN_READ, 0);
	if (ret) goto end;
	ret = FSFILE_Read(filehandle, &bytesRead, 0, badgeMngBuffer, badgeMngSize);
	if (ret) goto end;
	FSFILE_Close(filehandle);
	
	if (bytesRead != badgeMngSize) {ret = -4; goto end;}
	
	u32 badgeSetCount;
	memcpy(&badgeSetCount, badgeDataBuffer + 0x04, 4);
	if (badgeSetCount == 0) {ret = -1; goto end;}
	
	int i;
	for (i=0; i<1000; ++i) {
		
		if (badgeMngBuffer[0x358 + i/8] & (1 << (i%8))) {
			//badge slot i in use
			
			u32 badgeId;
			memcpy(&badgeId, badgeMngBuffer + 0x3E8 + i*0x28 + 0x4, 4);
			u16 badgeSubId;
			memcpy(&badgeSubId, badgeMngBuffer + 0x3E8 + i*0x28 + 0xE, 2);
			u32 shortcut;
			memcpy(&shortcut, badgeMngBuffer + 0x3E8 + i*0x28 + 0x18, 4);
			
			char filename[512];
			
			u16* utf16_name = (u16*) (badgeDataBuffer + 0x35E80 + i*16*0x8A);
			char utf8_name[256] = "";
			ret = ConvertUTF16toUTF8(utf16_name, (UTF8*) utf8_name, 256);
			
			removeInvalidChars(utf8_name);
			
			if (shortcut == 0xFFFFFFFF) {
				sprintf(filename, "badges/%s.%x.%x.png", utf8_name, (unsigned) badgeId, (unsigned) badgeSubId);
			} else {
				sprintf(filename, "badges/%s.%08x.%x.%x.png", utf8_name, (unsigned) shortcut, (unsigned) badgeId, (unsigned) badgeSubId);
			}
			print2("%s\n", filename);
			
			u16* rgb_ptr = (u16*) (badgeDataBuffer + 0x318F80 + i*0x2800);
			u8* alpha_ptr = badgeDataBuffer + 0x31AF80 + i*0x2800;
			
			ret = rgb565ToPng(filename, rgb_ptr, alpha_ptr);
			if (ret) print2("rgb565ToPng? %08x\n", ret);
		}
	}
	
	end:
	FSUSER_CloseArchive(NULL, &extdata_archive);
	if (badgeDataBuffer) free(badgeDataBuffer);
	if (badgeMngBuffer) free(badgeMngBuffer);
	return ret;
}

int writeToExtdata(int nnidNum) {
	
	u32 extdata_archive_lowpathdata[3] = {mediatype_SDMC, 0x000014d1, 0};
	FS_archive extdata_archive = (FS_archive){ARCH_EXTDATA, (FS_path){PATH_BINARY, 0xC, (u8*)extdata_archive_lowpathdata}};
	Handle filehandle;
	u32 tmpval=0;
	u64 badgeDataSize = 0xF4DF80;
	u64 badgeMngSize = 0xD4A8;
	Result ret = 0;
	
	u8 *badgeDataBuffer = NULL;
	u8 *badgeMngBuffer = NULL;
	char *direntries = NULL;
	
	u16 *rgb_buf_64x64 = NULL;
	u8 *alpha_buf_64x64 = NULL;
	u16 *rgb_buf_32x32 = NULL;
	u8 *alpha_buf_32x32 = NULL;
	
	DIR *dir;
	struct dirent *ent;
	dir = opendir("badges");
	if (dir == NULL) {print2("badges folder is missing.\n"); ret = -1; goto end;}
	
	badgeDataBuffer = malloc(badgeDataSize);
	if (badgeDataBuffer == NULL) {print2("Out of memory!\n"); ret = -2; goto end;}
	memset(badgeDataBuffer, 0, badgeDataSize);
	
	badgeMngBuffer = malloc(badgeMngSize);
	if (badgeMngBuffer == NULL) {print2("Out of memory!\n"); ret = -3; goto end;}
	memset(badgeMngBuffer, 0, badgeMngSize);
	
	direntries = malloc(1002*256);
	if (direntries == NULL) {print2("Out of memory!\n"); ret = -4; goto end;}
	memset(direntries, 0, 1002*256);
	int i;
	for (i=0; ((ent = readdir(dir)) != NULL) && (i<1002); ++i) {
		strncpy(direntries + i*256, ent->d_name, 255);
	}
	int filecount = i;
	qsort(direntries, filecount, 256, compareStrings);

	rgb_buf_64x64 = malloc(12*6*64*64*2);
	if (!rgb_buf_64x64) {print2("Out of memory!\n"); ret = -5; goto end;}
	alpha_buf_64x64 = malloc(12*6*64*64/2);
	if (!rgb_buf_64x64) {print2("Out of memory!\n"); ret = -6; goto end;}
	rgb_buf_32x32 = malloc(12*6*32*32*2);
	if (!rgb_buf_64x64) {print2("Out of memory!\n"); ret = -7; goto end;}
	alpha_buf_32x32 = malloc(12*6*32*32/2);
	if (!rgb_buf_64x64) {print2("Out of memory!\n"); ret = -8; goto end;}
	
	int badge_count = 0;
	
	for (i=0; i<filecount; ++i) {
		char *utf8_name = direntries + i*256;
		
		if (utf8_name[0] == '\0') {continue;}
		
		print2("trying to read png...\n");
		char path[0x1000];
		sprintf(path, "badges/%s", utf8_name);
		print2("%s\n", path);
		
		u16 utf16_name[0x8A/2];
		ret = ConvertUTF8toUTF16((const UTF8 *) utf8_name, utf16_name, 0x8A/2);
		
		u16* p;
		for (p=utf16_name; *p != '.' && *p != '\0'; ++p) {;}
		*p = '\0';
		
		u64 shortcut = getShortcut(utf8_name);
		
		int badges_in_image = pngToRGB565(path, rgb_buf_64x64, alpha_buf_64x64, rgb_buf_32x32, alpha_buf_32x32);
		int j;
		for (j=0; j<badges_in_image; ++j) {
			int k;
			for (k=0; k<16; ++k) {
				memcpy(badgeDataBuffer + 0x35E80 + badge_count*16*0x8A + k*0x8A, utf16_name, 0x8A);
			}
			memcpy(badgeDataBuffer + 0x318F80 + badge_count*0x2800, rgb_buf_64x64 + j*64*64, 64*64*2);
			memcpy(badgeDataBuffer + 0x31AF80 + badge_count*0x2800, alpha_buf_64x64 + j*64*64/2, 64*64/2);
			memcpy(badgeDataBuffer + 0xCDCF80 + badge_count*0xA00, rgb_buf_32x32 + j*32*32, 32*32*2);
			memcpy(badgeDataBuffer + 0xCDD780 + badge_count*0xA00, alpha_buf_32x32 + j*32*32/2, 32*32/2);
			
			int badge_id = badge_count+1;
			memcpy(badgeMngBuffer + 0x3E8 + badge_count*0x28 + 0x4, &badge_id, 4);
			badgeMngBuffer[0x3E8 + badge_count*0x28 + 0x8] = 0xBE;
			badgeMngBuffer[0x3E8 + badge_count*0x28 + 0x9] = 0xEF;
			memcpy(badgeMngBuffer + 0x3E8 + badge_count*0x28 + 0xC, &badge_count, 2);
			badgeMngBuffer[0x3E8 + badge_count*0x28 + 0x12] = 255;
			badgeMngBuffer[0x3E8 + badge_count*0x28 + 0x13] = 255;
			
			memcpy(badgeMngBuffer + 0x3E8 + badge_count*0x28 + 0x18, &shortcut, 8);
			memcpy(badgeMngBuffer + 0x3E8 + badge_count*0x28 + 0x20, &shortcut, 8);
			
			badgeMngBuffer[0x358 + badge_count/8] |= 1 << (badge_count % 8);
		
			++badge_count;
		}
	}
	
	print2("Attempting to write extdata...\n");
	
	ret = FSUSER_OpenArchive(NULL, &extdata_archive);
	if (ret != 0) {print2("FSUSER_OpenArchive failed! %08x\n", ret); goto end;}

	FS_path path = FS_makePath(PATH_CHAR, "/BadgeData.dat");
	
	ret = FSUSER_CreateFile(NULL, extdata_archive, path, badgeDataSize);
	ret = FSUSER_OpenFile(NULL, &filehandle, extdata_archive, path, FS_OPEN_WRITE, 0);
	if (ret != 0) {print2("FSUSER_OpenFile failed! %08x\n", ret); goto end;}
	ret = FSFILE_Write(filehandle, &tmpval, 0, badgeDataBuffer, badgeDataSize, FS_WRITE_FLUSH);
	ret = FSFILE_Close(filehandle);
	
	u32 total_badges = 0xFFFF * badge_count;
	
	badgeMngBuffer[0x04] = 0;
	memcpy(badgeMngBuffer + 0x8, &badge_count, 4);
	badgeMngBuffer[0x10] = 0xFF;
	badgeMngBuffer[0x11] = 0xFF;
	badgeMngBuffer[0x12] = 0xFF;
	badgeMngBuffer[0x13] = 0xFF;
	memcpy(badgeMngBuffer + 0x18, &total_badges, 4);
	memcpy(badgeMngBuffer + 0x1C, &nnidNum, 4);
	badgeMngBuffer[0x3D8] = 1;
	
	badgeMngBuffer[0xA028 + 0x0] = 0xFF;
	badgeMngBuffer[0xA028 + 0x1] = 0xFF;
	badgeMngBuffer[0xA028 + 0x2] = 0xFF;
	badgeMngBuffer[0xA028 + 0x3] = 0xFF;
	badgeMngBuffer[0xA028 + 0x4] = 0xFF;
	badgeMngBuffer[0xA028 + 0x5] = 0xFF;
	badgeMngBuffer[0xA028 + 0x6] = 0xFF;
	badgeMngBuffer[0xA028 + 0x7] = 0xFF;
	badgeMngBuffer[0xA028 + 0xC] = 0x10;
	badgeMngBuffer[0xA028 + 0xD] = 0x27;
	badgeMngBuffer[0xA028 + 0x10] = 0xBE;
	badgeMngBuffer[0xA028 + 0x11] = 0xEF;
	badgeMngBuffer[0xA028 + 0x18] = 0xFF;
	badgeMngBuffer[0xA028 + 0x19] = 0xFF;
	badgeMngBuffer[0xA028 + 0x1A] = 0xFF;
	badgeMngBuffer[0xA028 + 0x1B] = 0xFF;
	memcpy(badgeMngBuffer + 0xA028 + 0x1C, &badge_count, 4);
	memcpy(badgeMngBuffer + 0xA028 + 0x20, &total_badges, 4);

	path = FS_makePath(PATH_CHAR, "/BadgeMngFile.dat");
	FSUSER_CreateFile(NULL, extdata_archive, path, badgeMngSize);
	
	//if badge layout data already exists, copy it.
	ret = FSUSER_OpenFile(NULL, &filehandle, extdata_archive, path, FS_OPEN_READ, 0);
	if (ret==0) {
		FSFILE_Read(filehandle, &tmpval, 0xB2E8, badgeMngBuffer+0xB2E8, 360 * 0x18);
		FSFILE_Close(filehandle);
	}
	
	
	ret = FSUSER_OpenFile(NULL, &filehandle, extdata_archive, path, FS_OPEN_WRITE, 0);
	if (ret != 0) {print2("FSUSER_OpenFile failed! %08x\n", ret); goto end;}
	ret = FSFILE_Write(filehandle, &tmpval, 0, badgeMngBuffer, badgeMngSize, FS_WRITE_FLUSH);
	ret = FSFILE_Close(filehandle);
	
	end:
	FSUSER_CloseArchive(NULL, &extdata_archive);
	if (rgb_buf_64x64) free(rgb_buf_64x64);
	if (alpha_buf_64x64) free(alpha_buf_64x64);
	if (rgb_buf_32x32) free(rgb_buf_32x32);
	if (alpha_buf_32x32) free(alpha_buf_32x32);
	if (dir) closedir(dir);
	if (badgeDataBuffer) free(badgeDataBuffer);
	if (badgeMngBuffer) free(badgeMngBuffer);
	if (direntries) free(direntries);
	return ret;
}

void deleteBadgeExtdata() {
	print2("Secret code L+R+X+Y to delete badge\nextdata was entered. Are you sure?\nA=YES B=NO\n");
	
	while(aptMainLoop()) {
		gspWaitForVBlank();
		hidScanInput();
		u32 kDown = hidKeysDown();
		if (kDown == KEY_B) break;
		
		if (kDown == KEY_A) {
			print2("Deleting all badge extdata...\n");
			Result ret = DeleteExtSaveData(0x14d1);
			if (ret==0) {
				print2("Deleted.\n");
			} else {
				print2("Not deleted! %08x\n");
			}
			break;
		}
	}
}

int main() {

	gfxInitDefault();
	gfxSetDoubleBuffering(GFX_TOP, false);
	consoleInit(GFX_BOTTOM, NULL);
	srand(time(NULL));
	Result ret;
	
	hidScanInput();
	u32 kDown = hidKeysDown();
	
	if (kDown == (KEY_L | KEY_R | KEY_X | KEY_Y)) {
		deleteBadgeExtdata();
		goto end;
	}
	
	setupExtdata();
	
    u32 nnidNum = 0xFFFFFFFF;
    ret = actInit();
	if (ret) print2("actInit failed! %08x\n", ret);
    ret = ACTU_Initialize(0xB0002C8, 0, 0);
	if (ret) print2("ACTU_Initialize failed! %08x\n", ret);
    ret = ACTU_GetAccountDataBlock(0xFE, 4, 12, &nnidNum);
	if (ret) print2("ACTU_GetAccountDataBlock failed! %08x\n", ret);
    ret = actExit();
	if (ret) print2("actExit failed! %08x\n", ret);

	if (nnidNum != 0xFFFFFFFF) {
		print2("NNID found: %08X\n", (int) nnidNum);
	} else {
		print2("error, could not detect NNID!\n");
		goto end;
	}
	
	print2("Checking for preexisting Badge Arcade badges to dump...\n");
	ret = dumpPrexistingBadges();
	if (ret == 0) {
		print2("Successfully!\n");
	} else if (ret == -1 || ret == 0xC8804470) {
		print2("No official badges to dump.\n");
	} else if (ret == 0xC92044E6) {
		print2("-------------------------------------\nBadge file in use. Try loading all\nbadges in your badge case and waiting\nbefore launching.\n-------------------------------------\n");
		svcSleepThread(7000000000LL);
		goto end;
	} else {
		print2("WHAT IS WRONG WITH THE ELF. %08x\n", ret);
		svcSleepThread(6000000000LL);
		goto end;
	}
	
	print2("Writing to extdata...\n");
	ret = writeToExtdata(nnidNum);
	if (ret == 0xC92044E6) {
		print2("-------------------------------------\nBadge file in use. Try loading all\nbadges in your badge case and waiting\nbefore launching.\n-------------------------------------\n");
		svcSleepThread(7000000000LL);
		goto end;
	} else if (ret == 0) {
		print2("Successfully!\n");
	} else {
		print2("WHAT IS WRONG WITH THE ELF. %08x\n", ret);
		svcSleepThread(6000000000LL);
		goto end;
	}
	
	
	end:
	
	print2("\nPress any button to exit.\n");

	while(aptMainLoop()) {
		gspWaitForVBlank();
		hidScanInput();
		kDown = hidKeysDown();
		if (kDown !=0) break;
	}
	
	gfxExit();
	return 0;
}