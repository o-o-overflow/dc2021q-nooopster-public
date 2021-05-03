/* Source: opennap-0.44/codes.h */

#define NAP_LOGERROR 0x0
#define NAP_LOGIN 0x2
#define NAP_LOGSUCCESS 0x3
/* 0x4 version check [CLIENT] */
/* 0x5 "auto-upgrade" [SERVER] */
#define NAP_REG 0x6
#define NAP_MKUSER 0x7
#define NAP_UNOK 0x8
#define NAP_UNTK 0x9
#define NAP_UNBAD 0xa
#define NAP_SFILE 0x64
#define NAP_DFILE 0x66
#define NAP_UNSHARE 0x6e /* unshare all files [CLIENT] */
#define NAP_SEARCH 0xc8
#define NAP_SSEARCH 0xc9
#define NAP_SRET 0xc9
/* two names for 0xc9? */
#define NAP_SEND 0xca
#define NAP_DGET 0xcb
#define NAP_SGET 0xcc
#define NAP_TELL 0xcd
#define NAP_NGET 0xce
/* 0xcf-0xd0 (207-208) also #defined below */
#define NAP_NOTIFY 0xcf
/* 0xd0 hotlist [CLIENT] */
#define NAP_UON 0xd1
#define NAP_UOFF 0xd2
#define NAP_BROWSE 0xd3
#define NAP_RBROWSE 0xd4
#define NAP_DBROWSE 0xd5
#define NAP_COUNT 0xd6
/* 0xd7 request resume [CLIENT] */
/* 0xd8 resume search response [SERVER] */
/* 0xd9 end of resume search list [SERVER] */
#define NAP_DOWN 0xda
#define NAP_DOWNDONE 0xdb
#define NAP_UP 0xdc
#define NAP_UPDONE 0xdd
/* 0x12c optional ports [CLIENT] */
/* 0x12d-0x12f (301-303) also #defined below */
#define NAP_SUON 0x12d
#define NAP_SUERR 0x12e
#define NAP_RNOTIFY 0x12f
/* 0x140-0x147 (320-327) see below for #defines */
#define NAP_BLOCKLIST 0x14a
#define NAP_SBLOCKLIST 0x14b
/* 0x14b not in spec? */
#define NAP_BLOCK 0x14c
#define NAP_UNBLOCK 0x14d
#define NAP_JOIN 0x190
#define NAP_PART 0x191
#define NAP_SAY 0x192
#define NAP_SAID 0x193
#define NAP_NCHAN 0x194
#define NAP_JCHAN 0x195
#define NAP_SJOIN 0x196
#define NAP_SPART 0x197
#define NAP_USER 0x198
#define NAP_MNAME 0x199
#define NAP_TOPIC 0x19a
/* 0x1a4-0x1a9 (420-425) see below for #defines */
#define NAP_DSF 0x1f4
#define NAP_SSF 0x1f5
#define NAP_SX 0x258
#define NAP_RY 0x259
#define NAP_WHOIS 0x25b
#define NAP_SWHOIS 0x25c
#define NAP_SOFF 0x25d
#define NAP_LEVEL 0x25e
#define NAP_FREQ 0x25f
#define NAP_GFR 0x260
/* 0x261 accept failed [SERVER] */
#define NAP_NACC 0x261
#define NAP_KILL 0x262
#define NAP_NUKE 0x263
#define NAP_BAN 0x264
#define NAP_DATAP 0x265
#define NAP_PCHANGE 0x265
/* two names for 0x265 ? */
#define NAP_UNBAN 0x266
#define NAP_DBANLIST 0x267
#define NAP_SBANLIST 0x268
#define NAP_CLIST 0x269
#define NAP_SCLIST 0x26a
#define NAP_QLIMIT 0x26b
/* 0x26c queue limit [SERVER] */
#define NAP_RQLIMIT 0x26c
#define NAP_NOTICE 0x26d
#define NAP_MUZZLE 0x26e
#define NAP_UNMUZZLE 0x26f
#define NAP_UNNUKE 0x270
#define NAP_LSCHANGE 0x271
#define NAP_MISCONFIGURE 0x272
#define NAP_BPORT 0x272
#define NAP_SOP 0x273
#define NAP_ANNOUNCE 0x274
#define NAP_SBANLISTU 0x275

/* 0x280-0x282 (640-642) direct browse */
#define NAP_BROWSE2 0x280
#define NAP_BROWSE2ACC 0x281
#define NAP_BROWSE2ERR 0x282

#define NAP_CLOAK 0x28c
/* 0x2bc-0x2bf (700-703) change linkspeed/pw/e-mail/dataport */
/* 0x2ec (748) login attempt [SERVER] */
#define SERVER_PING 0x2ee
#define CLIENT_PING 0x2ef
#define CLIENT_PONG 0x2f0
#define SET_USER_PASSWORD 0x2f1

#define SERVER_RELOAD_CONFIG 0x320
#define SERVER_VERSION 0x321
#define SERVER_SET_CONFIG 0x32a

#define CHANNEL_CLEAR 0x334
#define CLIENT_REDIRECT 0x335
#define CLIENT_CYCLE 0x336
#define CHANNEL_SETLEVEL 0x337
/* 0x338 (824) */
#define CHAN_EMOTE 824
#define NAP_NAMES 0x339
/* 0x33a channel limit [CLIENT] */
/* 0x33b-0x33d (827-829) see below for #defines */
#define NAP_MNAME2 0x33e
#define CHANNEL_USERLIST 0x33e
/* two names for 0x33e ? */
#define SERVER_USERLIST 0x33f
/* 0x366 (870) add files by directory [CLIENT] */
/* 0x384-0x385 (900-901) connect/listen test [SERVER] */

/* 0x140-0x147 */
#define IGNORE_LIST 320
#define IGNORE_ENTRY 321
#define IGNORE_ADD 322
#define IGNORE_REMOVE 323
#define IGNORE_UNKNOWN 324
#define IGNORE_EXISTS 325
#define IGNORE_CLEAR 326
#define IGNORE_FAIL 327

/* 0x1a4-0x1a9 */
#define CHANNEL_BAN_LIST 420
#define CHANNEL_BAN_ENTRY 421
#define CHANNEL_BAN_ADD 422
#define CHANNEL_BAN_REMOVE 423
#define CHANNEL_BAN_CLEAR 424
#define CHANNEL_MOTD 425

/* 0x33b-0x33d */
#define CHANNEL_LIST2 827
#define CHANNEL_ENTRY2 828
#define CHANNEL_KICK 829

/* 0xcf-0xd0 */
#define ADD_NOTIFY 207
#define NOTIFY_CHECK 208
/* 0x12d-0x12f */
#define NOTIFY_EXISTS 301
#define NOTIFY_UNKNOWN 302
#define REMOVE_NOTIFY 303
