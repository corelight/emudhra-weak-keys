# @TEST-DOC: 12 established TLS 1.2 connections whose server chains contain each compromised TLS intermediate, issued by emSign and cross-signed by Sectigo; expect a seen and an accepted notice for each.
# @TEST-EXEC: zeek -r $TRACES/emudhra-2.pcap $PACKAGE
#
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p fuid file_mime_type note msg sub < notice.log > notice.cut
# @TEST-EXEC: btest-diff notice.cut
