/* packet-websocket.c
 * Routines for WebSocket dissection
 * Copyright 2012, Alexis La Goutte <alexis.lagoutte@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include "packet-http.h"
#include "packet-tcp.h"


/*
 * The information used comes from:
 * RFC6455: The WebSocket Protocol
 * http://www.iana.org/assignments/websocket (last updated 2012-04-12)
 */

void proto_register_skylink(void);
void proto_reg_handoff_skylink(void);

static dissector_handle_t skylink_handle;
static dissector_handle_t json_handle;
static dissector_handle_t ws_handle;


/* Initialize the protocol and registered fields */
static int proto_skylink = -1;
static int proto_http = -1;
static gint ett_skylink = -1;

static int hf_skylink_message_type = -1;
static int hf_skylink_message_rid = -1;
static int hf_skylink_message_mid = -1;

#define WS_TEXT     0x1

#define MASK_WS_FIN 0x80
#define MASK_WS_RSV 0x70
#define MASK_WS_OPCODE 0x0F
#define MASK_WS_MASK 0x80
#define MASK_WS_PAYLOAD_LEN 0x7F
#define MAX_UNMASKED_LEN (1024 * 256)

typedef struct json_value_t
{
  gchar * value;
  guint offset;
  guint length;
} json_value_t;

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

static json_value_t * getString(tvbuff_t *skylink_tvb, guint offset, const gchar *str_match, gint str_length)
{
  json_value_t *return_val;
  gint word_offset, val_end_offset;

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
    val_length = ((val_end_offset-1) - (word_offset + str_length + 2));

    return_val->value = (gchar *)tvb_get_string_enc(NULL, skylink_tvb, word_offset+str_length + 2, val_length, ENC_ASCII);
    return_val->offset = word_offset+str_length+2;
    return_val->length = val_length;
  }

  return return_val;
}

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
  }
  return tvb_new_real_data(new_data, j-2, j-2);
}

static int dissect_skylink_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *skylink_tree, guint8 opcode, guint payload_length, gboolean mask, const guint8* masking_key)
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
      if (tvb_strncaseeql(payload_tvb, offset, "0{", 2) == 0)
      {           
        skylink_tvb = tvb_new_subset_remaining(payload_tvb, 1);
        call_dissector(json_handle, skylink_tvb, pinfo, skylink_tree);
      }
      else if (tvb_strncaseeql(payload_tvb, offset, "42[", 3) == 0)
      {
        skylink_tvb = tvb_new_subset_remaining(payload_tvb, 14);
        skylink_tvb = tvb_jsonfix(skylink_tvb, pinfo, 0, payload_length-14);

        if (findString(skylink_tvb, 0, "\"type\"", 6) > 0)
        {
          json_value_t *type_val = getString(skylink_tvb, 0, "\"type\"", 6);
          proto_tree_add_item(skylink_tree, hf_skylink_message_type, skylink_tvb, type_val->offset, type_val->length, FALSE);
          col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", type_val->value);          
        }

        if (findString(skylink_tvb, 0, "\"rid\"", 5) > 0)
        {
          json_value_t *rid_val = getString(skylink_tvb, 0, "\"rid\"", 5);
          proto_tree_add_item(skylink_tree, hf_skylink_message_rid, skylink_tvb, rid_val->offset, rid_val->length, FALSE);
        }

        if (findString(skylink_tvb, 0, "\"mid\"", 5) > 0)
        {
          json_value_t *mid_val = getString(skylink_tvb, 0, "\"mid\"", 5);
          proto_tree_add_item(skylink_tree, hf_skylink_message_mid, skylink_tvb, mid_val->offset, mid_val->length, FALSE);
        }        

        call_dissector(json_handle, skylink_tvb, pinfo, skylink_tree);
      }
      offset += payload_length;
      break;
    default: /* Unknown */
      break;
  }
  return offset;
}


static int dissect_skylink_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti; //, *ti_len;
  guint8        opcode;
  gboolean      mask;
  guint         short_length, payload_length;
  guint         payload_offset, mask_offset;
  proto_tree   *skylink_tree;
  const guint8 *masking_key = NULL;
  tvbuff_t     *tvb_payload;

  short_length = tvb_get_guint8(tvb, 1) & MASK_WS_PAYLOAD_LEN;
  mask_offset = 2;
  if (short_length == 126) {
    payload_length = tvb_get_ntohs(tvb, 2);
    mask_offset += 2;
  } else if (short_length == 127) {
    /* warning C4244: '=' : conversion from 'guint64' to 'guint ', possible loss of data */
    payload_length = (guint)tvb_get_ntoh64(tvb, 2);
    mask_offset += 8;
  } else {
    payload_length = short_length;
  }

  /* Mask */
  mask = (tvb_get_guint8(tvb, 1) & MASK_WS_MASK) != 0;
  payload_offset = mask_offset + (mask ? 4 : 0);

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

  if (payload_length > 0) {
    tvb_payload = tvb_new_subset_remaining(tvb, payload_offset);
    dissect_skylink_payload(tvb_payload, pinfo, skylink_tree, opcode, payload_length, mask, masking_key);
  }

  return tvb_captured_length(tvb);
}

static int dissect_skylink(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  call_dissector(ws_handle, tvb, pinfo, tree);
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Skylink");
  dissect_skylink_frame(tvb,pinfo,tree, data);
  
  return tvb_captured_length(tvb);
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
      { "Message RID", "skylink.msgrid", 
        FT_STRING, BASE_NONE, NULL, 0x0, 
        NULL, HFILL
      }      
    },
    {
      &hf_skylink_message_mid, 
      { "Message MID", "skylink.msgmid", 
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
  skylink_handle = new_register_dissector("skylink", dissect_skylink, proto_skylink);
}

void proto_reg_handoff_skylink(void)
{
  dissector_add_for_decode_as("tcp.port", skylink_handle);
  json_handle = find_dissector("json");
  ws_handle = find_dissector("websocket");
  proto_http = proto_get_id_by_filter_name("http");
}