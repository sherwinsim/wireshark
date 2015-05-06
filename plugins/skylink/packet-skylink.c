/* packet-skylink.c
 * Routines for Skylink dissection
 * Author Sherwin Sim <sherwin.sim@temasys.com.sg>
 */

#include "config.h"

#include <stdio.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-http.h>
#include <epan/dissectors/packet-tcp.h>

void proto_register_skylink(void);
void proto_reg_handoff_skylink(void);

// Dissection Handles
static dissector_handle_t skylink_handle;
static dissector_handle_t json_handle;
static dissector_handle_t http_handle;
static dissector_handle_t sdp_handle;

// Wireshark Tree feel registers
static int proto_skylink = -1;
static int proto_http = -1;
static gint ett_skylink = -1;
static int hf_skylink_message_type = -1;
static int hf_skylink_message_rid = -1;
static int hf_skylink_message_mid = -1;
static int hf_skylink_message_sid = -1;
static int hf_skylink_message_receive_only = -1;
static int hf_skylink_message_trickle_ice = -1;
static int hf_skylink_message_data_channel = -1;
static int hf_skylink_message_useragent = -1;
static int hf_skylink_message_version = -1;

// Websocket op code
#define WS_TEXT     0x1

// Websocket Payload mask constants
#define MASK_WS_FIN 0x80
#define MASK_WS_RSV 0x70
#define MASK_WS_OPCODE 0x0F
#define MASK_WS_MASK 0x80
#define MASK_WS_PAYLOAD_LEN 0x7F
#define MAX_UNMASKED_LEN (1024 * 256)

// Struct that contains details for JSON values
typedef struct json_value_t
{
  gchar * value;
  guint offset;
  guint length;
} json_value_t;

// Search for a string in the buffer
static int findString(tvbuff_t *tvb, guint offset, const gchar *str_match, gint length)
{
  while (offset < tvb_length(tvb)) 
  {
    if (tvb_strncaseeql(tvb, offset, str_match, length) == 0) 
    {
      return offset;
    }
    offset++;
  }
  return 0;
}

// Fetch the JSON Value from a Json tree
static json_value_t * getJSONValue(tvbuff_t *skylink_tvb, guint offset, const gchar *str_match, gint str_length, gboolean string)
{
  json_value_t *return_val;
  gint word_offset;
  gint val_end_offset;
  gint val_offset;

  return_val=wmem_new(wmem_file_scope(), json_value_t);
  word_offset = findString(skylink_tvb, offset, str_match, str_length);

  if (word_offset > 0)
  {
    guint val_length = 0;
    val_end_offset = findString(skylink_tvb, word_offset, ",", 1);
    if (val_end_offset == 0)
    {
      val_end_offset = findString(skylink_tvb, word_offset, "}", 1);
    }

    if (string)
    {
      val_offset = (word_offset + str_length + 2);  
      val_length = ((val_end_offset-1) - val_offset);
    }
    else
    {
      val_offset = (word_offset + str_length + 1);  
      val_length = ((val_end_offset) - val_offset );
    }

    return_val->value = (gchar *)tvb_get_string_enc(NULL, skylink_tvb, val_offset, val_length, ENC_ASCII);
    return_val->offset = val_offset;
    return_val->length = val_length;
  }

  return return_val;
}

// Decode a masked Websocket payload
static tvbuff_t * tvb_unmasked(tvbuff_t *tvb, packet_info *pinfo, const guint offset, guint payload_length, const guint8 *masking_key)
{
  gchar        *data_unmask;
  guint         i;
  const guint8 *data_mask;
  guint         unmasked_length = payload_length > MAX_UNMASKED_LEN ? MAX_UNMASKED_LEN : payload_length;

  data_unmask = (gchar *)wmem_alloc(pinfo->pool, unmasked_length);
  data_mask   = tvb_get_ptr(tvb, offset, unmasked_length);
  /* Unmasked(XOR) Data... */
  for(i=0; i < unmasked_length; i++) {
    data_unmask[i] = data_mask[i] ^ masking_key[i%4];
  }

  return tvb_new_real_data(data_unmask, unmasked_length, payload_length);
}

// Prune out al the extra excapes, and convert the CRLF to real ones
static tvbuff_t * tvb_jsonfix(tvbuff_t *tvb, packet_info *pinfo, const guint offset, guint payload_length)
{
  const guint8       *orig_data;
  gchar              *new_data;
  guint              i;
  guint              j;
  
  orig_data = tvb_get_ptr(tvb, offset, payload_length);
  new_data = (gchar *)wmem_alloc(pinfo->pool, payload_length);

  j = 0;
  for(i=0; i < payload_length; i++) {
    if (orig_data[i] != 92)
    {
      new_data[j] = orig_data[i];
      j++;
    }
    // The two belowq conversions are pretty much for SDP parsing
    else if (orig_data[i] == 92 && orig_data[i+1] == 92 && orig_data[i+2] == 110 )
    {
      new_data[j] = '\n';
      i= i+2;
      j++;
    }
    else if (orig_data[i] == 92 && orig_data[i+1] == 92 && orig_data[i+2] == 114 )
    {
      new_data[j] = '\r';
      i= i+2;
      j++;
    }    
  }
  return tvb_new_real_data(new_data, j-2, j-2);
}

static int dissect_skylink_payload(tvbuff_t *full_tvb, tvbuff_t *tvb, packet_info *pinfo, proto_tree *skylink_tree, guint8 opcode, guint payload_length, gboolean mask, const guint8* masking_key)
{
  guint               offset = 0;
  tvbuff_t           *payload_tvb         = NULL;
  tvbuff_t           *skylink_tvb         = NULL;

  /* Payload */
  if (mask) 
  {
    payload_tvb = tvb_unmasked(tvb, pinfo, offset, payload_length, masking_key);
    tvb_set_child_real_data_tvbuff(tvb, payload_tvb);
    add_new_data_source(pinfo, payload_tvb, payload_length > tvb_captured_length(payload_tvb) ? "Unmasked Data (truncated)" : "Unmasked Data");
  } 
  else 
  {
    payload_tvb = tvb_new_subset(tvb, offset, payload_length, -1);
  }

  /* Application Data */
  switch (opcode) 
  {
    case WS_TEXT: /* Text */
      if (tvb_strncaseeql(payload_tvb, offset, "0{", 1) == 0)
      {
        skylink_tvb = tvb_new_subset_remaining(payload_tvb, 1);

        if (findString(skylink_tvb, 0, "\"sid\"", 5) > 0 && 
            findString(skylink_tvb, 0, "\"pingInterval\"", 14) > 0)
        {
          col_append_fstr(pinfo->cinfo, COL_INFO, "Socket ID Setup");          
        }

        if (findString(skylink_tvb, 0, "\"sid\"", 5) > 0)
        {
          json_value_t *sid_val = getJSONValue(skylink_tvb, 0, "\"sid\"", 5, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_sid, skylink_tvb, sid_val->offset, sid_val->length, FALSE);
        }
        call_dissector(json_handle, skylink_tvb, pinfo, skylink_tree);

      }
      else if (tvb_strncaseeql(payload_tvb, offset, "42[", 3) == 0)
      {
        skylink_tvb = tvb_new_subset_remaining(payload_tvb, 14);
        skylink_tvb = tvb_jsonfix(skylink_tvb, pinfo, 0, payload_length-14);

        if (findString(skylink_tvb, 0, "\"type\"", 6) > 0)
        {
          json_value_t *type_val = getJSONValue(skylink_tvb, 0, "\"type\"", 6, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_type, skylink_tvb, type_val->offset, type_val->length, FALSE);
          col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", type_val->value);          
        }

        if (findString(skylink_tvb, 0, "\"rid\"", 5) > 0)
        {
          json_value_t *rid_val = getJSONValue(skylink_tvb, 0, "\"rid\"", 5, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_rid, skylink_tvb, rid_val->offset, rid_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"mid\"", 5) > 0)
        {
          json_value_t *mid_val = getJSONValue(skylink_tvb, 0, "\"mid\"", 5, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_mid, skylink_tvb, mid_val->offset, mid_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"sid\"", 5) > 0)
        {
          json_value_t *sid_val = getJSONValue(skylink_tvb, 0, "\"sid\"", 5, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_sid, skylink_tvb, sid_val->offset, sid_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"receiveOnly\"", 13) > 0)
        {
          json_value_t *ronly_val = getJSONValue(skylink_tvb, 0, "\"receiveOnly\"", 13, FALSE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_receive_only, skylink_tvb, ronly_val->offset, ronly_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"enableIceTrickle\"", 18) > 0)
        {
          json_value_t *itrickle_val = getJSONValue(skylink_tvb, 0, "\"enableIceTrickle\"", 18, FALSE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_trickle_ice, skylink_tvb, itrickle_val->offset, itrickle_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"enableDataChannel\"", 19) > 0)
        {
          json_value_t *dc_val = getJSONValue(skylink_tvb, 0, "\"enableDataChannel\"", 19, FALSE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_data_channel, skylink_tvb, dc_val->offset, dc_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"agent\"", 7) > 0)
        {
          json_value_t *agent_val = getJSONValue(skylink_tvb, 0, "\"agent\"", 7, TRUE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_useragent, skylink_tvb, agent_val->offset, agent_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"version\"", 9) > 0)
        {
          json_value_t *version_val = getJSONValue(skylink_tvb, 0, "\"version\"", 9, FALSE);
          proto_tree_add_item(skylink_tree, hf_skylink_message_version, skylink_tvb, version_val->offset, version_val->length, FALSE);
        }                                

        if (findString(skylink_tvb, 0, "\"sdp\"", 5) > 0)
        {
          tvbuff_t *sdp_tvb = NULL;
          json_value_t *sdp_val = getJSONValue(skylink_tvb, 0, "\"sdp\"", 5, TRUE);
          sdp_tvb = tvb_new_subset(skylink_tvb, sdp_val->offset, sdp_val->length, -1);
          call_dissector(sdp_handle, sdp_tvb, pinfo, skylink_tree);
        }                
        call_dissector(json_handle, skylink_tvb, pinfo, skylink_tree);
      }
      offset += payload_length;
      break;
    default: /* Unknown */
      call_dissector(http_handle, full_tvb, pinfo, skylink_tree);
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "Skylink");
      break;
  }
  return offset;
}


static void dissect_skylink_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item   *ti; //, *ti_len;
  guint8        opcode;
  gboolean      mask;
  guint         length, short_length, payload_length;
  guint         payload_offset, mask_offset;
  proto_tree   *skylink_tree;
  const guint8 *masking_key = NULL;
  tvbuff_t     *tvb_payload;

  length = tvb_length(tvb);

  //fprintf(stderr, "Decoding a frame of size %d\n", length);

  short_length = tvb_get_guint8(tvb, 1) & MASK_WS_PAYLOAD_LEN;
  mask_offset = 2;
  if (short_length == 126) {
    payload_length = tvb_get_ntohs(tvb, 2);
    mask_offset += 2;
  } else if (short_length == 127) {
    payload_length = (guint)tvb_get_ntoh64(tvb, 2);
    mask_offset += 8;
  } else {
    payload_length = short_length;
  }

  /* Mask */
  mask = (tvb_get_guint8(tvb, 1) & MASK_WS_MASK) != 0;
  payload_offset = mask_offset + (mask ? 4 : 0);

  tvb_payload = tvb_new_subset_remaining(tvb, payload_offset);
  if (tvb_length(tvb_payload) < payload_length)
  {
      //fprintf(stderr, "We're looking for a frame with a payload size of %d and the packet size is %d \n", (payload_offset + payload_length), length );
      pinfo->desegment_len = payload_offset + payload_length - length;
      return;
  }  

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Skylink");
  col_set_str(pinfo->cinfo, COL_INFO, "");

  ti = proto_tree_add_item(tree, proto_skylink, tvb, 0, payload_offset, ENC_NA);
  skylink_tree = proto_item_add_subtree(ti, ett_skylink);

  /* Flags */
  opcode = tvb_get_guint8(tvb, 0) & MASK_WS_OPCODE;

  /* Masking-key */
  if (mask) 
  {
    masking_key = tvb_get_ptr(tvb, mask_offset, 4);
  }

  if (payload_length > 0) 
  {
    dissect_skylink_payload(tvb, tvb_payload, pinfo, skylink_tree, opcode, payload_length, mask, masking_key);
  }

  return;
}

static void dissect_skylink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return dissect_skylink_frame(tvb,pinfo,tree);
}

void proto_register_skylink(void)
{

  static hf_register_info hf[] = { 
    { 
      &hf_skylink_message_type, 
      { "Message Type", "skylink.msgtype", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }
    },
    {
      &hf_skylink_message_rid, 
      { "Room ID", "skylink.msgrid", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_mid, 
      { "MID", "skylink.msgmid", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_sid, 
      { "SID", "skylink.msgsid", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_receive_only, 
      { "Receive Only", "skylink.msgreceiveonly", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_trickle_ice, 
      { "Trickle Ice", "skylink.msgtrickleice", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_data_channel, 
      { "Data Channel", "skylink.msgdatachannel", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_useragent, 
      { "User Agent", "skylink.msguseragent", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_version, 
      { "Version", "skylink.msgversion", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    }
  };

  static gint *ett[] = {
    &ett_skylink,
  };
  
  proto_skylink = proto_register_protocol("Skylink", "Skylink", "skylink");
  proto_register_field_array(proto_skylink, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  skylink_handle = register_dissector("skylink", dissect_skylink, proto_skylink);
}

void proto_reg_handoff_skylink(void)
{
  dissector_add_handle("tcp.port", skylink_handle);
  json_handle = find_dissector("json");
  http_handle = find_dissector("http");
  sdp_handle = find_dissector("sdp");
  proto_http = proto_get_id_by_filter_name("http");
}
