##! Raise a notice when a certificate is encountered that contains the public
##! key of one of the eMudhra intermediate CAs whose private keys were found to
##! be compromised due to flawed key generation (Mozilla Bugzilla 2083449).
##!
##! Certificates are matched by the SHA-256 hash of their Subject Public Key
##! Info (SPKI). This detects all certificates for the compromised keys - the
##! intermediates issued by the emSign roots, their cross-signatures by Sectigo,
##! as well as any other certificate created for these keys. Every certificate
##! parsed by the X509 analyzer is checked. Certificates seen in SSL/TLS (both
##! server and client chains) are checked once the chain is complete - when the
##! connection is established, or when it ends otherwise. The notice contains
##! information about the chain, and a second notice is raised if the SSL/TLS
##! connection is established - i.e. the peer did not reject the chain.
##!
##! Additionally, SSL/TLS certificate chains that do not contain any of the
##! compromised keys are checked for certificates whose issuer is one of the
##! compromised intermediates. This detects chains from which the server (or
##! client) omitted the compromised intermediate, e.g. relying on the peer to
##! complete the chain via AIA fetching or intermediate caching. Since the
##! issuer name has to match for clients to build the chain, this also works for
##! rogue certificates created with the leaked keys.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice

module EMudhraWeakKeys;

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
		## Indicates that an SSL/TLS certificate chain contained a certificate
		## issued by one of the compromised eMudhra intermediate CAs (based on
		## the issuer name), while the chain did not contain a certificate with
		## the public key of any of the compromised intermediates.
		Compromised_Intermediate_Issuer,
		## Indicates that an SSL/TLS connection was established with a chain
		## for which :zeek:see:`EMudhraWeakKeys::Compromised_Intermediate_Issuer`
		## was raised.
		Compromised_Intermediate_Issuer_Accepted,
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

	## Subject names of the compromised intermediate CAs, mapped to the
	## SPKI hash of their key in :zeek:see:`EMudhraWeakKeys::compromised_keys`.
	## Names are normalized using :zeek:see:`EMudhraWeakKeys::normalize_name`.
	option compromised_subjects: table[string] of string = {
		["cn=emdvtlsca-g3b,o=emudhrabv,c=nl"] = "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
		["cn=emovtlsca-g3b,o=emudhrabv,c=nl"] = "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
		["cn=emevtlsca-g3b,o=emudhrabv,c=nl"] = "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
		["cn=emdvtlsca-g3c,o=emudhrainc,c=us"] = "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
		["cn=emovtlsca-g3c,o=emudhrainc,c=us"] = "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
		["cn=emevtlsca-g3c,o=emudhrainc,c=us"] = "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
		["cn=emovcsca-g3b,o=emudhrabv,c=nl"] = "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
		["cn=emovcsca-g3c,o=emudhrainc,c=us"] = "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
	};

	## Normalizes a distinguished name, as rendered by Zeek, for comparison:
	## lowercases it and removes all whitespace and backslashes. Clients
	## compare names case-insensitively and ignoring insignificant
	## whitespace, so a rogue certificate could vary them. This normalizes
	## more than clients do, which is fine for detection.
	global normalize_name: function(name: string): string;

	## Issuer names have to match this pattern to be checked against
	## :zeek:see:`EMudhraWeakKeys::compromised_subjects`. This avoids
	## normalizing the issuer name of every certificate. If you add subjects
	## that do not match, adjust this pattern.
	option issuer_prefilter = /emudhra/i;

	## How long notices are suppressed. Notices are suppressed per host
	## presenting the certificate chain (server address and port for server
	## chains, client address for client chains) and certificate. The
	## accepted notices are suppressed per client address, server address and
	## certificate, so that every client accepting a chain is reported.
	option suppression_interval = 1day;

	## Known certificates for the compromised keys (the intermediates issued
	## by the emSign roots and their cross-signatures by Sectigo), as the
	## lowercase hex SHA-256 hash of their DER encoding. This is only used to
	## describe the encountered certificate; detection is based on
	## :zeek:see:`EMudhraWeakKeys::compromised_keys`.
	option known_certs: set[string] = {
		"42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",	# issued by emSign Root TLS CA - G3
		"45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe",	# issued by AAA Certificate Services
		"98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",	# issued by emSign Root TLS CA - G3
		"5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699",	# issued by AAA Certificate Services
		"e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",	# issued by emSign Root TLS CA - G3
		"579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512",	# issued by AAA Certificate Services
		"0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",	# issued by emSign Root TLS CA - G3
		"62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72",	# issued by AAA Certificate Services
		"cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",	# issued by emSign Root TLS CA - G3
		"7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489",	# issued by AAA Certificate Services
		"432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",	# issued by emSign Root TLS CA - G3
		"fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f",	# issued by AAA Certificate Services
		"9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",	# issued by emSign Root CS CA - G3
		"a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8",	# issued by AAA Certificate Services
		"4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",	# issued by emSign Root CS CA - G3
		"84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd",	# issued by AAA Certificate Services
	};
}

redef record SSL::Info += {
	## Whether the certificate chains of this connection were checked.
	emudhra_checked: bool &default=F;
};

# Returns the identifier used to suppress notices about the certificate with
# the given hash in an SSL/TLS chain of c. See
# EMudhraWeakKeys::suppression_interval.
function chain_identifier(c: connection, side: string, accepted: bool, hash: string): string
	{
	if ( accepted )
		return cat_sep("|", "", c$id$orig_h, c$id$resp_h, hash);

	if ( side == "Client" )
		return cat_sep("|", "", c$id$orig_h, hash);

	return cat_sep("|", "", c$id$resp_h, c$id$resp_p, hash);
	}

function normalize_name(name: string): string
	{
	# Backslashes, as RFC 2253 escapes leading and trailing spaces.
	return gsub(to_lower(name), /[ \t\r\n\\]+/, "");
	}

# Returns the SHA-256 hash of the certificate. The certificate is re-encoded,
# so that trailing data does not influence the hash.
function cert_hash(cert_ref: opaque of x509): string
	{
	return sha256_hash(x509_get_certificate_string(cert_ref));
	}

# Returns the lowercase hex SHA-256 hash of the SPKI of the certificate.
function spki_hash(cert_ref: opaque of x509): string
	{
	# 4 is SHA-256 in the IANA TLS HashAlgorithm registry.
	return bytestring_to_hexstr(x509_spki_hash(cert_ref, 4));
	}

# Describes a certificate containing the compromised key ki.
function describe_key_cert(ki: KeyInfo, cert: X509::Certificate, hash: string): string
	{
	return fmt("%s eMudhra intermediate %s (CCADB %s), issued by %s",
	           hash in known_certs ? "compromised" : "unknown certificate with the key of compromised",
	           ki$name, ki$ccadb, cert$issuer);
	}

# Raises the notices for the certificate at the given position of an SSL/TLS
# certificate chain. The message is "<side> certificate chain contains <desc>
# at position <position><suffix>".
function report(c: connection, chain: vector of Files::Info, position: count, side: string,
                established: bool, seen: Notice::Type, accepted: Notice::Type,
                desc: string, suffix: string)
	{
	local f = chain[position];
	local hash = cert_hash(f$x509$handle);
	local leaf = chain[0]?$x509 ? chain[0]$x509$certificate$subject : "<unknown>";
	local sni = c$ssl?$server_name ? fmt(", SNI %s", c$ssl$server_name) : "";

	local n = Notice::Info($note=seen, $conn=c, $fuid=f$fuid,
	                       $msg=fmt("%s certificate chain contains %s at position %d%s", side, desc, position, suffix),
	                       $sub=fmt("leaf: %s%s; sha256: %s", leaf, sni, hash),
	                       $identifier=chain_identifier(c, side, F, hash),
	                       $suppress_for=suppression_interval);
	if ( f?$mime_type )
		n$file_mime_type = f$mime_type;

	NOTICE(n);

	if ( ! established )
		return;

	local a = copy(n);
	a$note = accepted;
	a$msg = fmt("SSL/TLS connection established with %s certificate chain containing %s at position %d%s",
	            to_lower(side), desc, position, suffix);
	a$identifier = chain_identifier(c, side, T, hash);
	NOTICE(a);
	}

# Reports certificates in the chain that contain one of the compromised keys.
# Returns whether there were any.
function check_chain_keys(c: connection, chain: vector of Files::Info, side: string, established: bool): bool
	{
	local found = F;

	for ( i in chain )
		{
		if ( ! chain[i]?$x509 )
			next;

		local info = chain[i]$x509;
		local spki = spki_hash(info$handle);
		if ( spki !in compromised_keys )
			next;

		found = T;
		report(c, chain, i, side, established,
		       Compromised_Intermediate_Cert, Compromised_Intermediate_Cert_Accepted,
		       describe_key_cert(compromised_keys[spki], info$certificate, cert_hash(info$handle)), "");
		}

	return found;
	}

# Reports certificates in the chain that were issued by one of the compromised
# intermediates.
function check_chain_issuers(c: connection, chain: vector of Files::Info, side: string, established: bool)
	{
	for ( i in chain )
		{
		if ( ! chain[i]?$x509 )
			next;

		local cert = chain[i]$x509$certificate;
		if ( issuer_prefilter !in cert$issuer )
			next;

		local issuer = normalize_name(cert$issuer);
		if ( issuer !in compromised_subjects || compromised_subjects[issuer] !in compromised_keys )
			next;

		local ki = compromised_keys[compromised_subjects[issuer]];
		report(c, chain, i, side, established,
		       Compromised_Intermediate_Issuer, Compromised_Intermediate_Issuer_Accepted,
		       fmt("%s, issued by compromised eMudhra intermediate %s (CCADB %s)", cert$subject, ki$name, ki$ccadb),
		       ", but not the intermediate itself");
		}
	}

# Checks a complete SSL/TLS certificate chain. Certificates issued by one of
# the compromised intermediates are only reported if the chain does not contain
# any of the compromised keys - otherwise, the intermediate is in the chain.
function check_chain(c: connection, chain: vector of Files::Info, side: string, established: bool)
	{
	if ( ! check_chain_keys(c, chain, side, established) )
		check_chain_issuers(c, chain, side, established);
	}

function check_chains(c: connection, established: bool)
	{
	if ( c$ssl$emudhra_checked )
		return;

	c$ssl$emudhra_checked = T;

	if ( c$ssl?$cert_chain )
		check_chain(c, c$ssl$cert_chain, "Server", established);

	if ( c$ssl?$client_cert_chain )
		check_chain(c, c$ssl$client_cert_chain, "Client", established);
	}

# Certificate chains are complete once the connection is established. The
# priority is higher than the one of the SSL handler that calls
# SSL::ssl_finishing, so that established connections are checked here.
event ssl_established(c: connection) &priority=25
	{
	check_chains(c, T);
	}

# For connections that are not established, this is called when the connection
# ends (or the SSL analyzer is removed due to a protocol violation; in that
# case, the chain may be incomplete).
hook SSL::ssl_finishing(c: connection)
	{
	check_chains(c, F);
	}

# Certificates seen outside of SSL/TLS, e.g. in RDP or Kerberos.
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	if ( f?$conns )
		for ( cid in f$conns )
			if ( f$conns[cid]?$ssl )
				return;

	local spki = spki_hash(cert_ref);
	if ( spki !in compromised_keys )
		return;

	local hash = cert_hash(cert_ref);
	local n = Notice::Info($note=Compromised_Intermediate_Cert, $f=f,
	                       $msg=fmt("Encountered %s", describe_key_cert(compromised_keys[spki], cert, hash)),
	                       $sub=fmt("sha256: %s", hash),
	                       $identifier=hash,
	                       $suppress_for=suppression_interval);

	if ( f?$conns && |f$conns| == 1 )
		for ( cid in f$conns )
			{
			n$conn = f$conns[cid];
			n$identifier = cat_sep("|", "", cid$resp_h, cid$resp_p, hash);
			}

	NOTICE(n);
	}
