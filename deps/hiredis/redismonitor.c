#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include "hiredis.h"
#include "async.h"
#include "adapters/libevent.h"
#include "iniparser.h"
#include "adlist.h"
#include "sds.h"
#include "zmalloc.h"

#define ARGV_MAXSIZE 10
#define SLEEPTIME 100000

int loglevel = 0;
char *logFilePrefix = "./redismonitor";
char logFilePath[64] = {0};
FILE *logFileHandle = NULL;

int cfgcount = 0;
list *cfgList = NULL;
list *targetList = NULL;

struct event_base *base = NULL;

typedef struct serverItem {
    char *ip;
    int port;
    int index;
    redisAsyncContext *c;
} serverItem;

typedef struct cfgItem {
    int index;
    serverItem source;
    list *targetList;
    list *cmdList;
    list *prefixList;
} cfgItem;

enum {LV_INFO,LV_DEBUG,LV_WARNING,LV_ERROR,LV_FATAL};


void reopenLogFile(void) {
	if (logFileHandle != NULL) {
		fclose(logFileHandle);
	}

	logFileHandle = fopen(logFilePath, "ab");
	if (logFileHandle == NULL) {
		fprintf(stderr, "cannot open file: %s\n", logFilePath);
	}
}

void initLogFile(struct tm *tmLocal) {
	char curLogFilePath[64] = {0};
	snprintf(curLogFilePath, 64, "%s%d-%d-%d.log", logFilePrefix, 1900+tmLocal->tm_year, tmLocal->tm_mon+1, tmLocal->tm_mday);
	
	if(strcmp(logFilePath, curLogFilePath))
	{
		memset(logFilePath, 0, sizeof(logFilePath));
		strncpy(logFilePath, curLogFilePath, strlen(curLogFilePath));

		reopenLogFile();
	}
}

void logPrint(const char * szFunc, int nLineNo, int nLevel, const char * format, ...) {
	if (nLevel < loglevel) return;

	time_t t;
	time(&t);
	struct tm tmLocal;
	gmtime_r(&t, &tmLocal);
	initLogFile(&tmLocal);

	va_list args;
	va_start(args, format);    
	char szBuffer[1024] = {0};    
	vsnprintf(szBuffer, sizeof(szBuffer), format, args);
	va_end(args);

	const char *szLevel;
	switch(nLevel)
	{
	case LV_INFO:
		{
			szLevel="[Info]";
			break;
		}
	case LV_DEBUG:
		{
			szLevel="[Debug]";
			break;
		}
	case LV_WARNING:
		{
			szLevel="[Warning]";
			break;
		}
	case LV_ERROR:
		{
			szLevel="[Error]";
			break;
		}
	case LV_FATAL:
		{
			szLevel="[Fatal]";
			break;
		}
	default:
		{
			szLevel="[Unknown]";
			break;
		}
	}

	char logBuffer[2048] = {0};    
	snprintf(logBuffer, sizeof(logBuffer), "[%04d-%02d-%02d %02d:%02d:%02d]%s[Function:%s][Line:%d]%s\n", 
		1900+tmLocal.tm_year, tmLocal.tm_mon+1, tmLocal.tm_mday, tmLocal.tm_hour, tmLocal.tm_min, tmLocal.tm_sec,
		szLevel, szFunc, nLineNo, szBuffer);

	if (logFileHandle) {
		int ret = fwrite(logBuffer, 1,  strlen(logBuffer), logFileHandle);
		if (ret != (int)strlen(logBuffer)) {
			fprintf(stderr, "write log failed");
			reopenLogFile();
			return;
		}
		fflush(logFileHandle);
	}
	else {
		reopenLogFile();
	}
}


int srcMatch(void *ptr, void *key) {
    if (!ptr || !key) return 0;
	
    if (!strcmp(((cfgItem*)ptr)->source.ip, ((cfgItem*)key)->source.ip) && (((cfgItem*)ptr)->source.port == ((cfgItem*)key)->source.port)) {
	return 1;
    }
    else {
	return 0;
    }
}

int targetMatch(void *ptr, void *key) {
    if (!ptr || !key) return 0;
	
    if (!strcmp(((serverItem*)ptr)->ip, ((serverItem*)key)->ip) && (((serverItem*)ptr)->port == ((serverItem*)key)->port)) {
	return 1;
    }
    else {
	return 0;
    }
}

int cmdMatch(void *ptr, void *key) {
    if (!ptr || !key) return 0;
	
    if (!strcasecmp((char*)ptr, (char*)key)) {
	return 1;
    }
    else {
	return 0;
    }
}

int prefixMatch(void *ptr, void *key) {
    if (!ptr || !key) return 0;
	
    if (!strncasecmp((char*)ptr, (char*)key, strlen((char*)ptr))) {
	return 1;
    }
    else {
	return 0;
    }
}

int parseAddr(const char *s, serverItem *item)
{
	for (size_t i = 0; i < strlen(s); i++) {
	    if (s[i] == ':') {
	        item->ip = zmalloc((size_t)i+1);
		 memcpy(item->ip, &s[0], i);
		 item->ip[i] = 0;
		 item->port = atoi(&s[i+1]);
		 return 0;
	    }
	}

	return -1;
}

void splitString(const char *s, list *strList) {
	int last = 0;
	size_t i;

	for (i = 0; i < strlen(s); i++) {
	    if (s[i] == ' ') {
	        last++;
	    }
	    else if (s[i] == ',') {
		 int len = i - last + 1;
	        char *data = zmalloc((size_t)len);
		 memcpy(data, &s[last], len-1);
		 data[len-1] = 0;

		 listAddNodeTail(strList, data);
		 last = i + 1;
	    }
	    else if (i == (strlen(s)-1)) {
	        int len = i - last + 2;
	        char *data = zmalloc((size_t)len);
		 memcpy(data, &s[last], len-1);
		 data[len-1] = 0;

		 listAddNodeTail(strList, data);	
	    }
	}
}

int initConfig(const char * ini_file) {
    dictionary	*ini ;
    int targetIdx = 0;

    ini = iniparser_load(ini_file);
    if (ini == NULL) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "cannot parse file: %s", ini_file);
        return -1 ;
    }

    cfgcount = iniparser_getint(ini, "main:cfgcount", -1);
    
    if (cfgcount <= 0) {
	 logPrint(__FUNCTION__,__LINE__, LV_ERROR, "no config");
        return -1;
    }

    loglevel = iniparser_getint(ini, "main:loglevel", 0);
    

    cfgList = listCreate();
    cfgList->match = srcMatch;
    targetList = listCreate();
    targetList->match = targetMatch;

    for (int i = 0; i < cfgcount; i++) {
        char szSrcKey[64];
        char szTargetKey[64];
        char szCmdKey[64];
	 char szPrefixKey[64];

	 char *s;
	 cfgItem *item = zmalloc((size_t)sizeof(cfgItem));
	 item->index = i;
	 
	 sprintf(szSrcKey, "cfg%d:src", i);
	 sprintf(szTargetKey, "cfg%d:target", i);
	 sprintf(szCmdKey, "cfg%d:cmd", i);
	 sprintf(szPrefixKey, "cfg%d:prefix", i);

	 s = iniparser_getstring(ini, szSrcKey, NULL);
	 if (s != NULL) {
	 	if (parseAddr(s, &item->source)) {
		    logPrint(__FUNCTION__,__LINE__, LV_ERROR, "invalid src: %s", s);
		    return -1;
	 	}
	 }

	 s = iniparser_getstring(ini, szTargetKey, NULL);
	 if (s != NULL) {
	 	list *strList = listCreate();
	 	splitString(s, strList);

              item->targetList = listCreate();
              listNode *ln;
		listIter li;
		listRewind(strList,&li);
		while ((ln = listNext(&li))) {
			serverItem *server = zmalloc((size_t)sizeof(serverItem));
			if (parseAddr((char*)ln->value, server)) {
				logPrint(__FUNCTION__,__LINE__, LV_ERROR, "invalid target: %s", (char*)ln->value);
				return -1;
			}
			listAddNodeTail(item->targetList, server);

			listNode *node = listSearchKey(targetList, server);
			if (node == NULL) {
				server->index = targetIdx++;
				server->c = NULL;
				listAddNodeTail(targetList, server);
			}
			else {
				server->index = ((serverItem *)(node->value))->index;
			}
		}
	 }

	 s = iniparser_getstring(ini, szCmdKey, NULL);
	 if (s != NULL) {
	 	item->cmdList = listCreate();
		item->cmdList->match = cmdMatch;
	 	splitString(s, item->cmdList);
	 }

	 s = iniparser_getstring(ini, szPrefixKey, NULL);
	 if (s != NULL) {
	 	item->prefixList= listCreate();
		item->prefixList->match = prefixMatch;
	 	splitString(s, item->prefixList);
	 }

	 listAddNodeTail(cfgList, item);	
    }

    iniparser_freedict(ini);
    return 0;
}

void printConfig(void) {
    fprintf(stderr, "cfgcount=%d\n", cfgcount);
    fprintf(stderr, "loglevel=%d\n", loglevel);
	
    int i = 0;
    listNode *ln;
    listIter li;
    listRewind(cfgList,&li);
    while ((ln = listNext(&li))) {
        cfgItem *item = ln->value;
	 fprintf(stderr, "[cfg%d]\n", i++);
	 fprintf(stderr, "src=%s:%d\n", item->source.ip, item->source.port);
	 
	 fprintf(stderr, "target=");
	 {
	 	listNode *subln;
		listIter subli;
		listRewind(item->targetList,&subli);
		while ((subln = listNext(&subli))) {
			serverItem *server = subln->value;
			fprintf(stderr, "%s:%d,", server->ip, server->port);
		}
	 }
	 fprintf(stderr, "\n");

	 fprintf(stderr, "cmd=");
	 {
	 	listNode *subln;
		listIter subli;
		listRewind(item->cmdList,&subli);
		while((subln = listNext(&subli))) {
			fprintf(stderr, "%s,", (char*)subln->value);
		}
	 }
	 fprintf(stderr, "\n");

	 fprintf(stderr, "prefix=");
	 {
	 	listNode *subln;
		listIter subli;
		listRewind(item->prefixList,&subli);
		while ((subln = listNext(&subli))) {
			fprintf(stderr, "%s,", (char*)subln->value);
		}
	 }
	 fprintf(stderr, "\n");
    }
}

void assignTargetCtx(char *ip, int port, redisAsyncContext *c) {
    serverItem item;
    item.ip = ip;
    item.port = port;
    listNode *node = listSearchKey(targetList, &item);
    if (node != NULL) {
        ((serverItem*)node->value)->c = c;
    }
}

void srcConnectCallback(redisAsyncContext *c, int status);
void targetConnectCallback(redisAsyncContext *c, int status);

void srcReconnect(const char *ip, int port) {
    redisAsyncContext *c = redisAsyncConnect(ip, port);
    if (c->err) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "AsyncConnect Error: %s, %s:%d", c->errstr, ip, port);
    }

    redisLibeventAttach(c,base);
    redisAsyncSetConnectCallback(c,srcConnectCallback);

    usleep(SLEEPTIME);
}

redisAsyncContext* targetReconnect(const char *ip, int port) {
    redisAsyncContext *c = redisAsyncConnect(ip, port);
    if (c->err) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "AsyncConnect Error: %s, %s:%d", c->errstr, ip, port);
    }

    redisLibeventAttach(c,base);
    redisAsyncSetConnectCallback(c,targetConnectCallback);

    usleep(SLEEPTIME);
    return c;
}

int initConnection(void) {
    listNode *ln;
    listIter li;
	
    listRewind(cfgList,&li);
    while ((ln = listNext(&li))) {
        cfgItem *item = ln->value;

	 srcReconnect(item->source.ip, item->source.port);
    }

    listRewind(targetList,&li);
    while ((ln = listNext(&li))) {
        serverItem *item = ln->value;

	 item->c = NULL;
	 targetReconnect(item->ip, item->port);
    }

    return 0;
}

void initArgv(int *argc, char ***argv, size_t **argvlen) {
	*argc = 0;
	*argv = zmalloc((size_t)sizeof(char*) * ARGV_MAXSIZE);
	for (int i = 0; i < ARGV_MAXSIZE; i++) {
		(*argv)[i] = NULL;
	}
	*argvlen = zmalloc((size_t)sizeof(size_t) * ARGV_MAXSIZE);
}

void releaseArgv(int *argc, char ***argv, size_t **argvlen) {
	*argc = 0;
	for (int i = 0; i < ARGV_MAXSIZE; i++) {
		if((*argv)[i]) {
			sdsfree((sds)((*argv)[i]));
		}
	}
	zfree(*argv);
	zfree(*argvlen);
}

int extractCmd(const char *szData, int *db, int *argc, char ***argv, size_t **argvlen) {
	int argvstart = 0;
	
	for (size_t i = 0; i < strlen(szData); i++) {
		if (*argc >= ARGV_MAXSIZE) {
			logPrint(__FUNCTION__,__LINE__, LV_WARNING, "Exceed argv maxsize: %s", szData);
			return -1;
		}
		
		if ((szData[i] == ' ') && (argvstart == 0)) {
		}
		else if ((szData[i] == '(') && (argvstart == 0)) {
			*db = atoi(&szData[i+4]);
		}
		else if ((szData[i] == '"') && (szData[i-1] != '\\')) {
			if (argvstart == 0) {
				(*argv)[*argc] = sdsnew("");
				argvstart = i+1;
			}
			else if (argvstart > 0) {
				(*argvlen)[*argc] = sdslen((*argv)[*argc]);
				argvstart = 0;
				(*argc)++;
			}
		}
		else if (argvstart > 0) {
			if ((szData[i] == '\\')) {
				switch (szData[i+1]) {
					case 'x': {
						char c = (szData[i+2] - 48) * 16 + (szData[i+3] - 48);
						(*argv)[*argc] = sdscatlen((*argv)[*argc], &c, 1);
						i+=3;
						break;
					}
					case 'r':
						(*argv)[*argc] = sdscatlen((*argv)[*argc], "\r", 1);
						i+=1;
						break;
					case 'n':
						(*argv)[*argc] = sdscatlen((*argv)[*argc], "\n", 1);
						i+=1;
						break;
					case 't':
						(*argv)[*argc] = sdscatlen((*argv)[*argc], "\t", 1);
						i+=1;
						break;
					case 'a':
						(*argv)[*argc] = sdscatlen((*argv)[*argc], "\a", 1);
						i+=1;
						break;
					case 'b':
						(*argv)[*argc] = sdscatlen((*argv)[*argc], "\b", 1);
						i+=1;
						break;
					default: 
						(*argv)[*argc] = sdscatlen((*argv)[*argc], &szData[i+1], 1);
						i+=1;
						break;
				}
			}
			else {
				(*argv)[*argc] = sdscatlen((*argv)[*argc], &szData[i], 1);
			}
		}
	}

	return 0;		
}

void cmdCallback(redisAsyncContext *c, void *r, void *privdata);

int syncCmd(int index, const char *szData) {
	listNode *node = listIndex(cfgList, index);
	if (node == NULL) {
		logPrint(__FUNCTION__,__LINE__, LV_WARNING, "Invalid src index: %d", index);
		return -1;
	}

	int db = 0;
       int argc;
	char **argv;
	size_t *argvlen;
	initArgv(&argc, &argv, &argvlen);
	int ret = extractCmd(szData, &db, &argc, &argv, &argvlen);
	if (ret) {
		goto err;
	}

	if (argc <= 0) {
		logPrint(__FUNCTION__,__LINE__, LV_WARNING, "Invalid argc: %s", szData);
		goto err;
	}

	/* check cmd */
	if (listIndex(((cfgItem*)node->value)->cmdList, 0) != NULL) {
		listNode *cmdNode = listSearchKey(((cfgItem*)node->value)->cmdList, argv[0]);
		if (cmdNode == NULL) {
			goto err;
		}
	}

	/* check prefix */
	if ((argc > 1) && (listIndex(((cfgItem*)node->value)->prefixList, 0) != NULL)) {
		listNode *prefixNode = listSearchKey(((cfgItem*)node->value)->prefixList, argv[1]);
		if (prefixNode == NULL) {
			goto err;
		}
	}

	listNode *ln;
       listIter li;
	listRewind(((cfgItem*)node->value)->targetList,&li);
       while ((ln = listNext(&li))) {
	   	serverItem *item = ln->value;

		listNode *target = listIndex(targetList, item->index);
		if (target == NULL) {
			continue;
		}

		if (((serverItem*)target->value)->c == NULL) {
			continue;
		}

		redisAsyncCommand(((serverItem*)target->value)->c, cmdCallback, ((serverItem*)target->value)->c->ip, "select %d", db);
		redisAsyncCommandArgv(((serverItem*)target->value)->c, cmdCallback, ((serverItem*)target->value)->c->ip, argc, (const char**)argv, argvlen);
       }

	releaseArgv(&argc, &argv, &argvlen);
	return 0;

err:
	releaseArgv(&argc, &argv, &argvlen);
	return -1;
}

void monitorCallback(redisAsyncContext *c, void *r, void *privdata) {
    ((void)c);
    redisReply *reply = r;
    if (reply == NULL) return;

    switch (reply->type) {
	 case REDIS_REPLY_STATUS:
		logPrint(__FUNCTION__,__LINE__, LV_INFO, "[src: %d]: %s", *(int*)privdata, reply->str);
		syncCmd(*(int*)privdata, reply->str);
		break;
	 case REDIS_REPLY_STRING:
	 case REDIS_REPLY_INTEGER:
	 case REDIS_REPLY_NIL:
	 case REDIS_REPLY_ARRAY:
	 case REDIS_REPLY_ERROR:
	 default:
		break;
    }
}

void cmdCallback(redisAsyncContext *c, void *r, void *privdata) {
    ((void)c);
    redisReply *reply = r;
    if (reply == NULL) return;

    switch (reply->type) {
        case REDIS_REPLY_STRING:
	 case REDIS_REPLY_STATUS:
		logPrint(__FUNCTION__,__LINE__, LV_INFO, "[target: %s]: %s", (char*)privdata, reply->str);
		break;
	 case REDIS_REPLY_INTEGER:
		logPrint(__FUNCTION__,__LINE__, LV_INFO, "[target: %s]: %lld", (char*)privdata, reply->integer);
		break;
	 case REDIS_REPLY_NIL:
	 case REDIS_REPLY_ARRAY:
	 case REDIS_REPLY_ERROR:
	 default:
		break;
    }
}

void srcDisconnectCallback(redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "src connection error: %s", c->errstr);
    }
    logPrint(__FUNCTION__,__LINE__, LV_ERROR, "src disconnected, %s:%d", c->ip, c->port);

    srcReconnect(c->ip, c->port);
}

void targetDisconnectCallback(redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "target connection error: %s", c->errstr);
    }
    logPrint(__FUNCTION__,__LINE__, LV_ERROR, "target disconnected, %s:%d", c->ip, c->port);

    assignTargetCtx(c->ip, c->port, NULL);

    targetReconnect(c->ip, c->port);
}

void srcConnectCallback(redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "src connect failed, %s:%d", c->ip, c->port);

	 srcReconnect(c->ip, c->port);
    }
    else {
	 logPrint(__FUNCTION__,__LINE__, LV_DEBUG, "src connected, %s:%d", c->ip, c->port);

        cfgItem item;
	 item.source.ip = c->ip;
	 item.source.port = c->port;
	 listNode *node = listSearchKey(cfgList, &item);
	 redisAsyncSetDisconnectCallback(c,srcDisconnectCallback);
	 redisAsyncCommand(c, monitorCallback, &(((cfgItem*)node)->source.index), "monitor");
    }
}

void targetConnectCallback(redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        logPrint(__FUNCTION__,__LINE__, LV_ERROR, "target connect failed, %s:%d", c->ip, c->port);

	 targetReconnect(c->ip, c->port);
    }
    else {
	 logPrint(__FUNCTION__,__LINE__, LV_DEBUG, "target connected, %s:%d", c->ip, c->port);

	 assignTargetCtx(c->ip, c->port, c);

	 redisAsyncSetDisconnectCallback(c,targetDisconnectCallback);

	 redisAsyncCommand(c, cmdCallback, c->ip, "enableRepl 0");
	 redisAsyncCommand(c, cmdCallback, c->ip, "enableMonitor 0");
    }
}

int main (int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    int ret = 0;
    if (argc == 2) {
        ret = initConfig(argv[1]);
    }
    else {
        ret = initConfig("./redismonitor.ini");
    }

    if (ret) {
	 logPrint(__FUNCTION__,__LINE__, LV_FATAL, "initConfig failed\n");
        return 1;
    }

    printConfig();
	
    base = event_base_new();

    initConnection();

    while (1) {
        event_base_dispatch(base);

        usleep(SLEEPTIME);
    }

    return 0;
}
