import { importJWK, importPKCS8, SignJWT } from "jose";

export const JWT_BEARER_URN =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer" as const;

export interface ClientAssertionResult {
	client_assertion: string;
	client_assertion_type: typeof JWT_BEARER_URN;
}

/**
 * Infer the JWT algorithm from a JWK object.
 *
 * Uses the `alg` header if present, otherwise derives a default from `kty`.
 */
function inferAlgorithmFromJwk(jwk: Record<string, unknown>): string {
	if (typeof jwk.alg === "string") return jwk.alg;
	switch (jwk.kty) {
		case "EC":
			return "ES256";
		case "OKP":
			return "EdDSA";
		default:
			return "RS256";
	}
}

/**
 * Builds a JWT client assertion for `private_key_jwt` authentication (RFC 7523 §2.2).
 *
 * The private key can be provided as:
 * - A PEM-encoded PKCS#8 string (e.g. `-----BEGIN PRIVATE KEY-----`)
 * - A JSON-serialised JWK string (e.g. `{"kty":"RSA","n":...}`)
 *
 * If `algorithm` is omitted it is inferred from the key:
 * - PEM → RS256
 * - JWK with `alg` field → that value
 * - JWK with `kty: "EC"` → ES256
 * - JWK with `kty: "OKP"` → EdDSA
 *
 * @see https://www.rfc-editor.org/rfc/rfc7523
 * @see https://www.rfc-editor.org/rfc/rfc7521
 */
export async function buildClientJwtAssertion({
	clientId,
	tokenEndpoint,
	privateKey,
	algorithm,
}: {
	clientId: string;
	tokenEndpoint: string;
	privateKey: string;
	algorithm?: string;
}): Promise<ClientAssertionResult> {
	const iat = Math.floor(Date.now() / 1000);

	const payload = {
		iss: clientId,
		sub: clientId,
		aud: tokenEndpoint,
		jti: crypto.randomUUID(),
		iat,
		exp: iat + 300,
	};

	let alg: string;
	let key: CryptoKey | Uint8Array;

	// Try parsing as JSON (JWK) first; fall back to PEM.
	let parsedJwk: Record<string, unknown> | null = null;
	try {
		parsedJwk = JSON.parse(privateKey) as Record<string, unknown>;
	} catch {
		// Not JSON — treat as PEM PKCS#8
	}

	let kid: string | undefined;

	if (parsedJwk) {
		alg = algorithm ?? inferAlgorithmFromJwk(parsedJwk);
		// Propagate the kid so IdPs like Okta can match it against their stored public key.
		if (typeof parsedJwk.kid === "string") {
			kid = parsedJwk.kid;
		}
		key = await importJWK(parsedJwk, alg);
	} else {
		alg = algorithm ?? "RS256";
		key = await importPKCS8(privateKey, alg);
	}

	const header: Record<string, unknown> = { alg };
	if (kid) header.kid = kid;

	const client_assertion = await new SignJWT(payload)
		.setProtectedHeader(header)
		.sign(key);

	return { client_assertion, client_assertion_type: JWT_BEARER_URN };
}

/**
 * Builds a JWT client assertion for `client_secret_jwt` authentication (RFC 7523 §2.2).
 *
 * Uses the client secret as an HMAC key. The default algorithm is HS256.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7523
 * @see https://www.rfc-editor.org/rfc/rfc7521
 */
export async function buildClientSecretJwtAssertion({
	clientId,
	tokenEndpoint,
	clientSecret,
	algorithm = "HS256",
}: {
	clientId: string;
	tokenEndpoint: string;
	clientSecret: string;
	algorithm?: string;
}): Promise<ClientAssertionResult> {
	const iat = Math.floor(Date.now() / 1000);

	const payload = {
		iss: clientId,
		sub: clientId,
		aud: tokenEndpoint,
		jti: crypto.randomUUID(),
		iat,
		exp: iat + 300,
	};

	const key = new TextEncoder().encode(clientSecret);
	const client_assertion = await new SignJWT(payload)
		.setProtectedHeader({ alg: algorithm })
		.sign(key);

	return { client_assertion, client_assertion_type: JWT_BEARER_URN };
}
