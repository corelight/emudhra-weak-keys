##! Raise a notice when a certificate is encountered that contains the public
##! key of one of the eMudhra intermediate CAs whose private keys are compromised.
##!
##! Certificates are matched by the SHA-256 hash of their Subject Public Key
##! Info (SPKI). Notices are output when affected certificates are seen,
##! and when connections are established.

@load base/protocols/ssl
@load base/files/x509
@load base/frameworks/notice

module EMudhraWeakKeys;

export {
	redef enum Notice::Type += {
		## Indicates that a certificate containing the public key of one of
		## the compromised eMudhra intermediate CAs was encountered.
		Compromised_Intermediate_Cert,
		## Indicates that an SSL/TLS handshake finished although the
		## server certificate chain contained a certificate with the public key
		## of one of the compromised eMudhra intermediate CAs. This does not
		## necessarily mean that the client accepted the certificate and that
		## data was exchanged.
		Compromised_Intermediate_Cert_Established,
		## Indicates that an SSL/TLS certificate chain contained a certificate
		## issued by one of the compromised eMudhra intermediate CAs (based on
		## the issuer name), while the chain did not contain a certificate with
		## the public key of any of the compromised intermediates.
		Compromised_Intermediate_Issuer,
		## Indicates that an SSL/TLS connection handshake finished where
		## :zeek:see:`EMudhraWeakKeys::Compromised_Intermediate_Issuer` was
		## raised. This does not necessarily mean that the client accepted the
		## certificate and that data was exchanged.
		Compromised_Intermediate_Issuer_Established,
	};

	## Compromised keys, indexed by SPKI, mapped to the subject common name
	## and organization of the intermediate CA.
	option compromised_keys: table[string] of string = {
		["ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105"] = "EM DV TLS CA - G3B (eMudhra BV)",
		["43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b"] = "EM OV TLS CA - G3B (eMudhra BV)",
		["e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41"] = "EM EV TLS CA - G3B (eMudhra BV)",
		["49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f"] = "EM DV TLS CA - G3C (eMudhra Inc)",
		["63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8"] = "EM OV TLS CA - G3C (eMudhra Inc)",
		["5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0"] = "EM EV TLS CA - G3C (eMudhra Inc)",
		["ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6"] = "EM OV CS CA - G3B (eMudhra BV)",
		["92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30"] = "EM OV CS CA - G3C (eMudhra Inc)",
	};

	## Subject names of the compromised intermediate CAs, mapped to the
	## SPKI in :zeek:see:`EMudhraWeakKeys::compromised_keys`.
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
	## lowercases it and removes all whitespace (including escaped spaces;
	## other escapes are kept). Clients
	## compare names case-insensitively and ignoring insignificant
	## whitespace.
	global normalize_name: function(name: string): string;

	## Issuer names have to match this pattern to be checked against
	## :zeek:see:`EMudhraWeakKeys::compromised_subjects`. This avoids
	## normalizing the issuer name of every certificate.
	option issuer_prefilter = /emudhra/i;

	## How long notices are suppressed. Notices are suppressed per server
	## (address and port), side of the connection presenting the certificate,
	## and compromised key.
	## The established notices are suppressed per client address, server address
	## and compromised key, so that every client accepting a chain is
	## reported.
	option suppression_interval = 1day;
}

redef record SSL::Info += {
	## Whether the certificate chains of this connection were checked.
	emudhra_checked: bool &default=F;
};

# Returns the identifier used to suppress notices about a certificate with, or
# issued by, the compromised key spki, presented by side ("Server" or "Client")
# of c. See EMudhraWeakKeys::suppression_interval.
function notice_identifier(c: connection, side: string, established: bool, spki: string): string
	{
	if ( established )
		return cat_sep("|", "", c$id$orig_h, c$id$resp_h, spki);

	return cat_sep("|", "", side, c$id$resp_h, c$id$resp_p, spki);
	}

function normalize_name(name: string): string
	{
	# RFC 2253 escapes leading and trailing spaces with a backslash. Other
	# escapes, e.g. of commas within a value, are kept, so that they cannot be
	# confused with separators.
	local s = gsub(to_lower(name), /\\ /, "");
	return gsub(s, /[ \t\r\n]+/, "");
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

# Describes a certificate containing the key of the intermediate name.
function describe_key_cert(name: string, cert: X509::Certificate): string
	{
	return fmt("intermediate %s, issued by %s", name, cert$issuer);
	}

# Raises the notices for the certificate at the given position of an SSL/TLS
# certificate chain, which contains, or was issued by, the compromised key spki.
# The message is "<side> certificate chain contains <desc> at position
# <position><suffix>".
function report(c: connection, chain: vector of Files::Info, position: count, side: string,
                established: bool, seen_note: Notice::Type, established_note: Notice::Type,
                spki: string, desc: string, suffix: string)
	{
	local f = chain[position];
	local hash = cert_hash(f$x509$handle);
	local leaf = chain[0]?$x509 ? chain[0]$x509$certificate$subject : "<unknown>";
	local sni = c$ssl?$server_name ? fmt(", SNI %s", c$ssl$server_name) : "";

	local notice_sub = fmt("leaf: %s%s; sha256: %s", leaf, sni, hash);
	local mime = f?$mime_type ? f$mime_type : "";

	local n = Notice::Info($note=seen_note, $conn=c, $fuid=f$fuid,
	                       $msg=fmt("%s certificate chain contains %s at position %d%s", side, desc, position, suffix),
	                       $sub=notice_sub,
	                       $identifier=notice_identifier(c, side, F, spki),
	                       $suppress_for=suppression_interval);
	if ( mime != "" )
		n$file_mime_type = mime;

	NOTICE(n);

	# Clients control whether they send a certificate chain, and servers may
	# not validate it, so this is only interesting for server chains.
	if ( ! established || side != "Server" )
		return;

	local e = Notice::Info($note=established_note, $conn=c, $fuid=f$fuid,
	                       $msg=fmt("SSL/TLS connection established with %s certificate chain containing %s at position %d%s",
	                                to_lower(side), desc, position, suffix),
	                       $sub=notice_sub,
	                       $identifier=notice_identifier(c, side, T, spki),
	                       $suppress_for=suppression_interval);
	if ( mime != "" )
		e$file_mime_type = mime;

	NOTICE(e);
	}

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
		       Compromised_Intermediate_Cert, Compromised_Intermediate_Cert_Established, spki,
		       describe_key_cert(compromised_keys[spki], info$certificate), "");
		}

	return found;
	}

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

		local spki = compromised_subjects[issuer];
		report(c, chain, i, side, established,
		       Compromised_Intermediate_Issuer, Compromised_Intermediate_Issuer_Established, spki,
		       fmt("%s, issued by compromised eMudhra intermediate %s", cert$subject, compromised_keys[spki]),
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

# Certificate chains are complete once the connection is established. Priority
# 25 to be able to run this before the SSL::ssl_finishing hook that's called
# by Zeek in ssl_establisjed.
event ssl_established(c: connection) &priority=25
	{
	check_chains(c, T);
	}

# For connections that are not established.
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
	                       $msg=fmt("Encountered %s", describe_key_cert(compromised_keys[spki], cert)),
	                       $sub=fmt("sha256: %s", hash),
	                       $identifier=spki,
	                       $suppress_for=suppression_interval);

	if ( f?$conns && |f$conns| == 1 )
		for ( cid in f$conns )
			{
			n$conn = f$conns[cid];
			n$identifier = notice_identifier(n$conn, f$is_orig ? "Client" : "Server", F, spki);
			}

	NOTICE(n);
	}
