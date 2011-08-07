#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/etypes.h>

#define N2N_PORT 1234

#define N2N_FLAGS_FROM_SUPERNODE 0x0020
#define N2N_PKTTYPE_MASK 0x001f

static int proto_n2n = -1;
static int hf_n2n_version = -1;
static int hf_n2n_ttl = -1;
static int hf_n2n_flag_supernode = -1;
static int hf_n2n_pkttype = -1;
static int hf_n2n_community = -1;
static int hf_n2n_transportid = -1;
static int hf_n2n_dstmac = -1;
static int hf_n2n_srcmac = -1;
static int hf_n2n_ethertype = -1;
static gint ett_n2n = -1;

static const value_string packettypenames[] = {
    { 1, "Register" },
    { 2, "Deregister" },
    { 3, "Packet" },
    { 4, "Register_ACK" },
    { 5, "Register_SUPER" },
    { 6, "Register_SUPER_ACK" },
    { 7, "Register_SUPER_NAK" },
    { 8, "Federation" },
    { 9, "Peer Info" },
    {10, "Query Peer" }
};

void
proto_register_n2n(void)
{
    static hf_register_info hf[] = {
        { &hf_n2n_version,
            { "N2N Version", "n2n.version",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_n2n_ttl,
            { "Time to Live", "n2n.ttl",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_n2n_flag_supernode,
            { "From Supernode", "n2n.flags.from_supernode",
                FT_BOOLEAN, 16,
                NULL, N2N_FLAGS_FROM_SUPERNODE,
                NULL, HFILL }
        },
        { &hf_n2n_pkttype,
            { "Packet Type", "n2n.pkttype",
                FT_UINT16, BASE_DEC,
                VALS(packettypenames), N2N_PKTTYPE_MASK,
                NULL, HFILL }
        },
        { &hf_n2n_community,
            { "Community", "n2n.community",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_n2n_transportid,
            { "Transport ID", "n2n.transportid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL}
        },
        { &hf_n2n_dstmac,
            { "Destination MAC", "n2n.dstmac",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        { &hf_n2n_srcmac,
            { "Source MAC", "n2n.srcmac",
                FT_ETHER, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL}
        },
        { &hf_n2n_ethertype,
            { "Encapsulated Protocol", "n2n.ethertype",
                FT_UINT16, BASE_HEX,
                VALS(etype_vals), 0x0,
                NULL, HFILL}
        }
    };

    /* Setup protcol subtree array */
    static gint *ett[] = {
        &ett_n2n
    };

    proto_n2n = proto_register_protocol (
        "N2N Protocol", /* name       */
        "N2N",      /* short name */
        "n2n"       /* abbrev     */
        );
    proto_register_field_array(proto_n2n, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void
dissect_n2n(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "N2N");
    /* Clear out stuff in the info column */
    /* col_clear(pinfo->cinfo,COL_INFO); */

    if(tree) {
        proto_item *ti = NULL;
        proto_item *n2n_tree = NULL;

        ti = proto_tree_add_item(tree, proto_n2n, tvb, 0, -1, FALSE);
        n2n_tree = proto_item_add_subtree(ti, ett_n2n);
        proto_tree_add_item(n2n_tree, hf_n2n_version, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(n2n_tree, hf_n2n_ttl, tvb, offset, 1, FALSE);
        offset += 1;
        proto_tree_add_item(n2n_tree, hf_n2n_flag_supernode, tvb, offset, 2, FALSE);
        proto_tree_add_item(n2n_tree, hf_n2n_pkttype, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item(n2n_tree, hf_n2n_community, tvb, offset, 16, FALSE);
        offset += 16;
        proto_tree_add_item(n2n_tree, hf_n2n_transportid, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item(n2n_tree, hf_n2n_dstmac, tvb, offset, 6, FALSE);
        offset += 6;
        proto_tree_add_item(n2n_tree, hf_n2n_srcmac, tvb, offset, 6, FALSE);
        offset += 6;
        proto_tree_add_item(n2n_tree, hf_n2n_ethertype, tvb, offset, 2, FALSE);
        offset += 2;
    }
}

void
proto_reg_handoff_n2n(void)
{
    static dissector_handle_t n2n_handle;

    n2n_handle = create_dissector_handle(dissect_n2n, proto_n2n);
    dissector_add_uint("udp.port", N2N_PORT, n2n_handle);
}
