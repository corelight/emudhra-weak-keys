##! Raise a notice when one of the eMudhra intermediate CA certificates whose
##! private keys were found to be compromised due to flawed key generation
##! (Mozilla Bugzilla 2083449) is encountered.
##!
##! Certificates are matched by the SHA-256 hash of their DER encoding, as
##! re-encoded by OpenSSL; trailing data after the certificate does not
##! influence the hash. Every certificate parsed by the X509 analyzer is
##! checked. For certificates seen in SSL/TLS (both server and client chains),
##! the notice contains information about the chain.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice

module EmudraWeakKeys;

export {
	redef enum Notice::Type += {
		## Indicates that one of the eMudhra intermediate CA certificates with
		## a compromised private key was encountered.
		Compromised_Intermediate_Cert,
	};

	## Information about a compromised certificate.
	type CertInfo: record {
		## Subject common name and organization of the certificate.
		name: string;
		## CCADB record ID of the certificate.
		ccadb: string;
		## Serial number of the certificate (lowercase hex).
		serial: string;
		## Common name of the certificate issuer.
		issuer: string;
	};

	## Compromised certificates, indexed by the lowercase hex SHA-256 hash of
	## their DER encoding.
	option compromised_certs: table[string] of CertInfo = {
		["e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838"] = CertInfo($name="EM EV TLS CA - G3B (eMudhra BV)", $ccadb="A012304", $serial="c7c41efe92d825f05eae841a4a82c1", $issuer="emSign Root TLS CA - G3"),
		["98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b"] = CertInfo($name="EM OV TLS CA - G3B (eMudhra BV)", $ccadb="A012308", $serial="6cada367fb1c100088120ea202d568", $issuer="emSign Root TLS CA - G3"),
		["42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"] = CertInfo($name="EM DV TLS CA - G3B (eMudhra BV)", $ccadb="A012302", $serial="a4aee678f23362b4c0e460b772f214", $issuer="emSign Root TLS CA - G3"),
		["432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3"] = CertInfo($name="EM EV TLS CA - G3C (eMudhra Inc)", $ccadb="A012296", $serial="8009928a64107601af05fa2f19f109", $issuer="emSign Root TLS CA - G3"),
		["cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f"] = CertInfo($name="EM OV TLS CA - G3C (eMudhra Inc)", $ccadb="A012300", $serial="296926c227a3a1526392b19482a504", $issuer="emSign Root TLS CA - G3"),
		["0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19"] = CertInfo($name="EM DV TLS CA - G3C (eMudhra Inc)", $ccadb="A012294", $serial="588b2e3c2bb8cda13e1a1209254321", $issuer="emSign Root TLS CA - G3"),
		["9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4"] = CertInfo($name="EM OV CS CA - G3B (eMudhra BV)", $ccadb="A012306", $serial="7818933f8f85b4619a2b35fba83d0a", $issuer="emSign Root CS CA - G3"),
		["4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1"] = CertInfo($name="EM OV CS CA - G3C (eMudhra Inc)", $ccadb="A012298", $serial="544b7f922c31ae220a4a922916f6e6", $issuer="emSign Root CS CA - G3"),
	};
}

# Returns the SHA-256 hash of the DER encoding of the certificate. Reuses the
# fingerprint computed by the base scripts if it is SHA-256.
function cert_sha256(f: fa_file, cert_ref: opaque of x509): string
	{
	if ( X509::hash_function == sha256_hash && f$info?$x509 )
		return f$info$x509$fingerprint;

	return sha256_hash(x509_get_certificate_string(cert_ref));
	}

# Priority is lower than the base X509 handler, which sets the fingerprint,
# and the SSL file_sniff handler, which adds the certificate to the chain.
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=3
	{
	local hash = cert_sha256(f, cert_ref);
	if ( hash !in compromised_certs )
		return;

	local ci = compromised_certs[hash];
	local desc = fmt("compromised eMudhra intermediate %s (CCADB %s)", ci$name, ci$ccadb);
	local n = Notice::Info($note=Compromised_Intermediate_Cert, $f=f,
	                       $msg=fmt("Encountered %s", desc),
	                       $sub=fmt("sha256: %s", hash),
	                       $identifier=hash,
	                       $suppress_for=1day);

	if ( f?$conns && |f$conns| == 1 )
		{
		local c: connection &is_assigned;	# to help static analysis
		for ( _, c in f$conns )
			break;

		n$conn = c;
		n$identifier = cat(c$id$resp_h, c$id$resp_p, hash);

		if ( c?$ssl && c$ssl?$cert_chain )
			{
			local chain = f$is_orig ? c$ssl$client_cert_chain : c$ssl$cert_chain;
			for ( i in chain )
				{
				if ( chain[i]$fuid != f$id )
					next;

				local leaf = ( chain[0]?$x509 ) ? chain[0]$x509$certificate$subject : "<unknown>";
				local sni = c$ssl?$server_name ? fmt(", SNI %s", c$ssl$server_name) : "";
				n$msg = fmt("%s certificate chain contains %s at position %d",
				            f$is_orig ? "Client" : "Server", desc, i);
				n$sub = fmt("leaf: %s%s; sha256: %s", leaf, sni, hash);
				break;
				}
			}
		}

	NOTICE(n);
	}
