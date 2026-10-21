# @TEST-DOC: 12 established TLS 1.2 connections whose servers send only leaf certificates issued by the compromised TLS intermediates, omitting the intermediates; expect an issuer and an accepted issuer notice for each.
# @TEST-EXEC: zeek -r $TRACES/emudhra-3.pcap $PACKAGE
#
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p fuid file_mime_type note msg sub < notice.log > notice.cut
# @TEST-EXEC: btest-diff notice.cut
