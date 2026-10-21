##! Raise a notice when a certificate is encountered that contains the public
##! key of one of the eMudhra intermediate CAs whose private keys were found to
##! be compromised due to flawed key generation (Mozilla Bugzilla 2083449).
##!
##! Certificates are matched by the SHA-256 hash of their Subject Public Key
##! Info (SPKI). This detects all certificates for the compromised keys - the
##! intermediates issued by the emSign roots, their cross-signatures by Sectigo,
##! as well as any other certificate created for these keys. Every certificate
##! parsed by the X509 analyzer is checked. For certificates seen in SSL/TLS
##! (both server and client chains), the notice contains information about the
##! chain, and a second notice is raised if the SSL/TLS connection is
##! established - i.e. the peer did not reject the chain.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice

module EmudraWeakKeys;

export {
	redef enum Notice::Type += {
		## Indicates that a certificate containing the public key of one of
		## the compromised eMudhra intermediate CAs was encountered.
		Compromised_Intermediate_Cert,
		## Indicates that an SSL/TLS connection was established although the
		## server or client certificate chain contained a certificate with the
		## public key of one of the compromised eMudhra intermediate CAs. This
		## means that the peer accepted the chain, or did not validate it.
		Compromised_Intermediate_Cert_Accepted,
	};

	## Information about a compromised key.
	type KeyInfo: record {
		## Subject common name and organization of the intermediate CA.
		name: string;
		## CCADB record ID of the intermediate issued by the emSign root.
		ccadb: string;
	};

	## Compromised keys, indexed by the lowercase hex SHA-256 hash of their
	## DER-encoded Subject Public Key Info.
	option compromised_keys: table[string] of KeyInfo = {
		["ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"] = KeyInfo($name="EM DV TLS CA - G3B (eMudhra BV)", $ccadb="A012302"),
		["43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b"] = KeyInfo($name="EM OV TLS CA - G3B (eMudhra BV)", $ccadb="A012308"),
		["e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41"] = KeyInfo($name="EM EV TLS CA - G3B (eMudhra BV)", $ccadb="A012304"),
		["49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f"] = KeyInfo($name="EM DV TLS CA - G3C (eMudhra Inc)", $ccadb="A012294"),
		["63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8"] = KeyInfo($name="EM OV TLS CA - G3C (eMudhra Inc)", $ccadb="A012300"),
		["5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0"] = KeyInfo($name="EM EV TLS CA - G3C (eMudhra Inc)", $ccadb="A012296"),
		["ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6"] = KeyInfo($name="EM OV CS CA - G3B (eMudhra BV)", $ccadb="A012306"),
		["92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30"] = KeyInfo($name="EM OV CS CA - G3C (eMudhra Inc)", $ccadb="A012298"),
	};

	## Information about a known certificate for one of the compromised keys.
	type CertInfo: record {
		## Common name of the certificate issuer.
		issuer: string;
		## Serial number of the certificate (lowercase hex).
		serial: string;
	};

	## Known certificates for the compromised keys, indexed by the lowercase
	## hex SHA-256 hash of their DER encoding. This is only used to describe
	## the encountered certificate; detection is based on
	## :zeek:see:`EmudraWeakKeys::compromised_keys`.
	option known_certs: table[string] of CertInfo = {
		["42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="a4aee678f23362b4c0e460b772f214"),
		["45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe"] = CertInfo($issuer="AAA Certificate Services", $serial="a024fdf4ba665c785ce4a020483858b7"),
		["98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="6cada367fb1c100088120ea202d568"),
		["5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699"] = CertInfo($issuer="AAA Certificate Services", $serial="e94223bde92f914e5ab9acabfdac3710"),
		["e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="c7c41efe92d825f05eae841a4a82c1"),
		["579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512"] = CertInfo($issuer="AAA Certificate Services", $serial="d8f8685e4f2bd9d82402a85a1c1eb731"),
		["0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="588b2e3c2bb8cda13e1a1209254321"),
		["62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72"] = CertInfo($issuer="AAA Certificate Services", $serial="91f347f1a5b7d39962b95e0ee4e299d1"),
		["cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="296926c227a3a1526392b19482a504"),
		["7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489"] = CertInfo($issuer="AAA Certificate Services", $serial="8d5a4811939ef447d77111cdd9849ae9"),
		["432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3"] = CertInfo($issuer="emSign Root TLS CA - G3", $serial="8009928a64107601af05fa2f19f109"),
		["fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f"] = CertInfo($issuer="AAA Certificate Services", $serial="05f078752dece7a1bb8595d303167171"),
		["9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4"] = CertInfo($issuer="emSign Root CS CA - G3", $serial="7818933f8f85b4619a2b35fba83d0a"),
		["a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8"] = CertInfo($issuer="AAA Certificate Services", $serial="41e32b73ac185d6ce0d7480bacf84e69"),
		["4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1"] = CertInfo($issuer="emSign Root CS CA - G3", $serial="544b7f922c31ae220a4a922916f6e6"),
		["84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd"] = CertInfo($issuer="AAA Certificate Services", $serial="d6a5ef613b390f32ef9cdf349f772841"),
	};
}

# A compromised certificate seen in an SSL/TLS certificate chain.
type ChainMatch: record {
	# "Server" or "Client".
	side: string;
	# Description of the certificate.
	desc: string;
	# Position in the chain.
	position: count;
	# Sub field of the notice.
	sub: string;
	fuid: string;
	identifier: string;
};

redef record SSL::Info += {
	## Compromised certificates seen in the certificate chains of this
	## connection.
	emudhra_matches: vector of ChainMatch &optional;
};

# Priority is lower than the SSL file_sniff handler, which adds the
# certificate to the chain.
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=3
	{
	# 4 is SHA-256 in the IANA TLS HashAlgorithm registry.
	local spki = bytestring_to_hexstr(x509_spki_hash(cert_ref, 4));
	if ( spki !in compromised_keys )
		return;

	local ki = compromised_keys[spki];
	# Hash the re-encoded certificate, so that trailing data does not matter.
	local hash = sha256_hash(x509_get_certificate_string(cert_ref));

	local desc: string;
	if ( hash in known_certs )
		desc = fmt("compromised eMudhra intermediate %s (CCADB %s), issued by %s",
		           ki$name, ki$ccadb, known_certs[hash]$issuer);
	else
		desc = fmt("unknown certificate with the key of compromised eMudhra intermediate %s (CCADB %s), issued by %s",
		           ki$name, ki$ccadb, cert$issuer);

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
				local m = ChainMatch($side=f$is_orig ? "Client" : "Server", $desc=desc, $position=i,
				                     $sub=fmt("leaf: %s%s; sha256: %s", leaf, sni, hash),
				                     $fuid=f$id, $identifier=n$identifier);
				n$msg = fmt("%s certificate chain contains %s at position %d", m$side, desc, i);
				n$sub = m$sub;

				if ( ! c$ssl?$emudhra_matches )
					c$ssl$emudhra_matches = vector();
				c$ssl$emudhra_matches += m;
				break;
				}
			}
		}

	NOTICE(n);
	}

event ssl_established(c: connection)
	{
	if ( ! c$ssl?$emudhra_matches )
		return;

	for ( i in c$ssl$emudhra_matches )
		{
		local m = c$ssl$emudhra_matches[i];
		NOTICE(Notice::Info($note=Compromised_Intermediate_Cert_Accepted,
		                    $conn=c, $fuid=m$fuid,
		                    $msg=fmt("SSL/TLS connection established with %s certificate chain containing %s at position %d",
		                             to_lower(m$side), m$desc, m$position),
		                    $sub=m$sub,
		                    $identifier=m$identifier,
		                    $suppress_for=1day));
		}
	}
