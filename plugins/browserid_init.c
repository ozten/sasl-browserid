
#include <config.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef macintosh
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <assert.h>

#include <sasl.h>
#include <saslplug.h>
#include <saslutil.h>



#ifdef macintosh
#include <sasl_browserid_plugin_decl.h>
#endif

#ifdef WIN32
#define PLUG_API __declspec(dllexport)
#else
#define PLUG_API extern
#endif

#define SASL_CLIENT_PLUG_INIT( x ) \
extern sasl_client_plug_init_t x##_client_plug_init; \
PLUG_API int sasl_client_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
			 sasl_client_plug_t **pluglist, \
                         int *plugcount) { \
        return x##_client_plug_init(utils, maxversion, out_version, \
				     pluglist, plugcount); \
}

#define SASL_SERVER_PLUG_INIT( x ) \
extern sasl_server_plug_init_t x##_server_plug_init; \
PLUG_API int sasl_server_plug_init(const sasl_utils_t *utils, \
                         int maxversion, int *out_version, \
			 sasl_server_plug_t **pluglist, \
                         int *plugcount) { \
        return x##_server_plug_init(utils, maxversion, out_version, \
				     pluglist, plugcount); \
}

#ifdef WIN32
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}
#endif

SASL_CLIENT_PLUG_INIT( browserid )
SASL_SERVER_PLUG_INIT( browserid )

