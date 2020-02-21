#define MIN(x, y) ((x)<(y)?(x):(y))
#define COUNTOF(x) (sizeof(x)/sizeof(x[0]))
#define DELAY(x) vTaskDelay((x)/portTICK_PERIOD_MS)

#define ENUMCASE(evtname) case evtname: /* printf(#evtname); */ break
#define ENUMCASEO(evtname) case evtname: /* printf(#evtname) */ (void) 0
#define ENUMDEFAULT(x) default: /* printf("unknown (%d)", (int) x) */ (void) 0


