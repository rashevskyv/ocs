#include <stdio.h>
#include <string.h>

#include "cfgs.h"
#include "system.h"
#include "utils.h"

const char * getRegion(void)
{
	const char * regions[] = 
	{
		"JPN",
		"USA",
		"EUR",
		"AUS",
		"CHN",
		"KOR",
		"TWN",
		"Unknown"
	};

	CFG_Region region = 0;
	
	if (R_SUCCEEDED(CFGU_SecureInfoGetRegion(&region)))
	{
		if (region < 7)
			return regions[region];
	}
	
	return regions[7];
}

const char getFirmRegion(void)
{
	if (strncmp(getRegion(), "JPN", 3) == 0)
		return 'J';
	else if (strncmp(getRegion(), "USA", 3) == 0)
		return 'U';
	else if ((strncmp(getRegion(), "EUR", 3) == 0) || (strncmp(getRegion(), "AUS", 3) == 0))
		return 'E';
	else if (strncmp(getRegion(), "CHN", 3) == 0)
		return 'C';
	else if (strncmp(getRegion(), "KOR", 3) == 0)
		return 'K';
	else if (strncmp(getRegion(), "TWN", 3) == 0)
		return 'T';
	
	return 0;
}

char * getScreenType(void)
{	
	static char upperScreen[20];
	static char lowerScreen[20];
	
	static char screenType[32];
	
	if (isN3DS())
	{
		u8 screens = 0;
		
		if(R_SUCCEEDED(gspLcdInit()))
		{
			if (R_SUCCEEDED(GSPLCD_GetVendors(&screens)))
				gspLcdExit();
		}	
        
		switch ((screens >> 4) & 0xF)
		{
			case 0x01: // 0x01 = JDI => IPS
				sprintf(upperScreen, "Upper: IPS");
				break;
			case 0x0C: // 0x0C = SHARP => TN
				sprintf(upperScreen, "Upper: TN");
				break;
			default:
				sprintf(upperScreen, "Upper: Unknown");
				break;
		}
		switch (screens & 0xF)
		{
			case 0x01: // 0x01 = JDI => IPS
				sprintf(lowerScreen, " | Lower: IPS");
				break;
			case 0x0C: // 0x0C = SHARP => TN
				sprintf(lowerScreen, " | Lower: TN");
				break;
			default:
				sprintf(lowerScreen, " | Lower: Unknown");
				break;
		}
		
		strcpy(screenType, upperScreen);
		strcat(screenType, lowerScreen);
	}
	else
		sprintf(screenType, "Upper: TN | Lower: TN"); 
	
	return screenType;
}