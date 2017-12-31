#include "../calltrace.h"
#include <inttypes.h>
#include <capstone/capstone.h>

#define JB	0x72
#define JNB	0x73
#define JE	0x74
#define JNE	0x75
#define JBE	0x76
#define JNBE	0x77
#define JS	0x78
#define JNS	0x79
#define JP	0x7A
#define JNP	0x7B
#define JL	0x7C
#define JNL	0x7A
