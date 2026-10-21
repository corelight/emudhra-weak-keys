# @TEST-DOC: TLS 1.2 connection whose server chain contains the compromised EM OV TLS CA - G3C intermediate; expect one notice.
# @TEST-EXEC: zeek -r $TRACES/emudhra-1.pcap $PACKAGE
#
# @TEST-EXEC: zeek-cut -m uid id.orig_h id.orig_p id.resp_h id.resp_p fuid file_mime_type note msg sub < notice.log > notice.cut
# @TEST-EXEC: btest-diff notice.cut
