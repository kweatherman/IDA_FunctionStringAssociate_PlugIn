
// Function String Associate plug-in
#include "stdafx.h"
#include <WaitBoxEx.h>

const UINT MAX_LINE_STR_COUNT = 12;
const UINT MAX_LABEL_STR = 60;  // Max size of each label
const int  MAX_COMMENT   = 1024; // Max size of whole comment line

static const char SITE_URL[] = { "https://github.com/kweatherman/IDA_FunctionStringAssociate_PlugIn/" };

// Working label element info container
struct __declspec(align(16)) STRC
{
	char str[MAX_LABEL_STR];
	int  refs;
};

// === Function Prototypes ===
static void processFunction(func_t *pFunc);
static void filterWhitespace(LPSTR pszString);

// === Data ===
static ALIGN(32) STRC stringArray[MAX_LINE_STR_COUNT];
static UINT commentCount = 0;

// Main dialog
static const char mainDialog[] =
{
	"BUTTON YES* Continue\n" // "Continue" instead of "okay"
	"Function String Associate\n"

    #ifdef _DEBUG
    "** DEBUG BUILD **\n"
    #endif
	"Extracts strings from each function and intelligently adds them  \nto the function comment line.\n\n"
    "Version %Aby Sirmabus\n"
    "<#Click to open site.#FunctionStringAssociate Github:k:1:1::>\n\n"

	" \n\n\n\n\n"
};


// Initialize
plugmod_t* idaapi init()
{
    return PLUGIN_OK;
}

void idaapi term()
{
}

static void idaapi doHyperlink(int button_code, form_actions_t &fa) { open_url(SITE_URL); }

// Plug-in process
bool idaapi run(size_t arg)
{
    try
    {
		qstring version;
		msg("\n>> Function String Associate: v%s, built %s.\n", GetVersionString(MY_VERSION, version).c_str(), __DATE__);

        if (auto_is_ok())
        {           
            int result = ask_form(mainDialog, version.c_str(), doHyperlink);
            if (!result)
            {
                msg(" - Canceled -\n");
                return false;
            }
            WaitBox::show();

            // Iterate through all functions..            
            UINT functionCount = (UINT) get_func_qty();
            char buffer[32];
            msg("Processing %s functions.\n", NumberCommaString(functionCount, buffer));

			TIMESTAMP startTime = GetTimeStamp();
            for (UINT n = 0; n < functionCount; n++)
            {
                processFunction(getn_func(n));

                if (functionCount % 1000)
                {
                    if (WaitBox::isUpdateTime())
                    {
                        if (WaitBox::updateAndCancelCheck((int)(((float)n / (float)functionCount) * 100.0f)))
                        {
                            msg("* Aborted *\n");
                            break;
                        }
                    }
                }
            }
            
            msg("Done. Generated %s function string comments in %s.\n", NumberCommaString(commentCount, buffer), TimeString(GetTimeStamp() - startTime));            
        }
        else
        {
            warning("Auto analysis must finish first before you run this plug-in!");
            msg("\n*** Aborted ***\n");
			return false;
        }
    }
    CATCH()

    WaitBox::hide();
    refresh_idaview_anyway();
	return true;
}


// Remove whitespace & unprintable chars from the input string
static void filterWhitespace(LPSTR pstr)
{
	LPSTR ps = pstr;
	while(*ps)
	{
		// Replace unwanted chars with a space char
		char c = *ps;
		if((c < ' ') || (c > '~'))
			*ps = ' ';

		ps++;
	};

	// Trim any starting space(s)
	ps = pstr;
	while(*ps)
	{
		if(*ps == ' ')
	        memmove(ps, ps+1, strlen(ps));
		else
			break;
	};

	// Trim any trailing space
	ps = (pstr + (strlen(pstr) - 1));
	while(ps >= pstr)
	{
		if(*ps == ' ')
			*ps-- = 0;
		else
			break;
	};
}

static int __cdecl compare(const void *a, const void *b)
{
    STRC *sa = (STRC *)a;
    STRC *sb = (STRC *)b;
    return (sa->refs - sb->refs);
}


// Process function
static void processFunction(func_t *f)
{
    const int MIN_STR_SIZE = 4;

	// Skip tiny functions for speed
	if(f->size() >= 8)
	{
		// Skip if it already has type comment
		// TODO: Could have option to just skip comment if one already exists?
		BOOL skip = FALSE;
		qstring tmp;
		if(get_func_cmt(&tmp, f, true) <= 0)		
			get_func_cmt(&tmp, f, false);

		if(tmp.size() > sizeof("Microsoft VisualC"))
		{
			// Ignore common auto-generated comments
            if (strncmp(tmp.c_str(), "Microsoft VisualC ", SIZESTR("Microsoft VisualC ")) != 0)
            {
                if (strstr(tmp.c_str(), "\ndoubtful name") == NULL)
                    skip = TRUE;
            }

            //if (skip)
            //    msg(EAFORMAT" c: \"%s\"\n", f->startEA, tempComment);		
		}

		// TODO: Add option to append to existing comments?

		if(!skip)
		{
			// Iterate function body looking for string references
            UINT nStr = 0;
            func_item_iterator_t it(f);

		    do
		    {
			    // Has an xref?
                ea_t currentEA = it.current();
			    xrefblk_t xb;
			    if(xb.first_from(currentEA, XREF_DATA))
			    {			
                    // Points to a string?
                    if (isString(xb.to))
                    {
                        // Get string type                       
                        int strtype = get_str_type_code(getStringType(xb.to));
                        UINT len = (UINT) get_max_strlit_length(xb.to, strtype, ALOPT_IGNHEADS);
                        if (getChracterLength(strtype, len) > (MIN_STR_SIZE + 1))
                        {
                            // Will convert from UTF to ASCII as needed
							// #TODO: Make this UTF-8 aware (UTF8 length, strcpy, etc).
							qstring str;							
                            if (get_strlit_contents(&str, xb.to, len, strtype, NULL, STRCONV_ESCAPE) > 1)
                            {
                                // Clean it up
								char buffer[MAXSTR]; buffer[SIZESTR(buffer)] = 0;
								strncpy(buffer, str.c_str(), SIZESTR(buffer));
                                filterWhitespace(buffer);

                                // If it's not tiny continue
                                if (strlen(buffer) >= MIN_STR_SIZE)
                                {
                                    // If already in the list, just update it's ref count
                                    BOOL skip = FALSE;
                                    for (UINT j = 0; j < nStr; j++)
                                    {
                                        if (strcmp(stringArray[j].str, buffer) == 0)
                                        {
                                            stringArray[j].refs++;
                                            skip = TRUE;
                                            break;
                                        }
                                    }

                                    if (!skip)
                                    {
                                        // Add it to the list
                                        strcpy(stringArray[nStr].str, buffer);
                                        stringArray[nStr].refs = 1;
                                        ++nStr;

                                        // Bail out if we're at max string count
                                        if (nStr >= MAX_LINE_STR_COUNT)
                                            break;
                                    }
                                }
                            }
                        }
				    }
			    }

		    }while(it.next_addr());

			// Got at least one string?
            if(nStr)
			{
				// Sort by reference count
                if (nStr > 1)
                    qsort(stringArray, nStr, sizeof(STRC), compare);

				// Concatenate a final comment string
                char comment[MAX_COMMENT + MAX_LABEL_STR] = { "#STR: " };
                for (UINT i = 0; i < nStr; i++)
                {
                    STRC *sc = &stringArray[i];
                    int freeSize = ((MAX_COMMENT - (int) strlen(comment)) - 1);
                    if ((freeSize > 6) && (freeSize < (int)(strlen(sc->str) + 2)))
                        break;
                    else
                    {
                        char temp[MAX_LABEL_STR]; temp[SIZESTR(temp)] = 0;
                        _snprintf(temp, SIZESTR(temp), "\"%s\"", sc->str);
                        strncat(comment, temp, freeSize);
                    }

                    // Continue line?
                    if ((i + 1) < nStr)
                    {
                        freeSize = ((MAX_COMMENT - (int) strlen(comment)) - 1);
                        if (freeSize > 6)
                            strncat(comment, ", ", freeSize);
                        else
                            break;
                    }
                }

				// Add/replace comment
                //msg(EAFORMAT" %u\n", f->start_ea, nStr);
				set_func_cmt(f, "", true); set_func_cmt(f, "", false);
				set_func_cmt(f, comment, true);
				commentCount++;
			}
		}
	}
}


// ============================================================================
const static char IDAP_name[] = "Function String Associate";

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
    PLUGIN_UNL,				// Plug-in flags
    init,					// Initialization function
    term,					// Clean-up function
    run,					// Main plug-in body
    IDAP_name,	            // Comment - unused
    IDAP_name,	            // As above - unused
    IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
    NULL                    // Hot key to run the plug-in
};