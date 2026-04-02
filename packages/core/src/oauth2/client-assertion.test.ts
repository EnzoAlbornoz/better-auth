import {
	decodeJwt,
	exportJWK,
	exportPKCS8,
	generateKeyPair,
	importJWK,
	jwtVerify,
} from "jose";
import { describe, expect, it } from "vitest";
import {
	JWT_BEARER_URN,
	buildClientJwtAssertion,
	buildClientSecretJwtAssertion,
} from "./client-assertion";

describe("buildClientJwtAssertion", () => {
	it("signs with an RSA PEM PKCS#8 private key and produces a valid JWT", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256", {
			extractable: true,
		});
		const pem = await exportPKCS8(privateKey);

		const result = await buildClientJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: pem,
		});

		expect(result.client_assertion_type).toBe(JWT_BEARER_URN);

		const { payload } = await jwtVerify(result.client_assertion, publicKey);
		expect(payload.iss).toBe("my-client");
		expect(payload.sub).toBe("my-client");
		expect(payload.aud).toBe("https://idp.example.com/token");
		expect(typeof payload.jti).toBe("string");
		expect(typeof payload.iat).toBe("number");
		expect(typeof payload.exp).toBe("number");
		expect((payload.exp as number) - (payload.iat as number)).toBe(300);
	});

	it("signs with an EC JWK JSON string and infers ES256 algorithm", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const privateJwk = await exportJWK(privateKey);
		const publicJwk = await exportJWK(publicKey);

		const result = await buildClientJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: JSON.stringify(privateJwk),
		});

		expect(result.client_assertion_type).toBe(JWT_BEARER_URN);

		const pubKey = await importJWK(publicJwk, "ES256");
		const { payload } = await jwtVerify(result.client_assertion, pubKey);
		expect(payload.iss).toBe("my-client");
		expect(payload.sub).toBe("my-client");
		expect(payload.aud).toBe("https://idp.example.com/token");
	});

	it("uses the alg field from the JWK when present", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS256", {
			extractable: true,
		});
		const privateJwk = { ...(await exportJWK(privateKey)), alg: "RS256" };

		const result = await buildClientJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: JSON.stringify(privateJwk),
		});

		const { payload } = await jwtVerify(result.client_assertion, publicKey);
		expect(payload.iss).toBe("my-client");
	});

	it("respects an explicit algorithm override for PEM keys", async () => {
		const { privateKey, publicKey } = await generateKeyPair("RS384", {
			extractable: true,
		});
		const pem = await exportPKCS8(privateKey);

		const result = await buildClientJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: pem,
			algorithm: "RS384",
		});

		const { payload } = await jwtVerify(result.client_assertion, publicKey, {
			algorithms: ["RS384"],
		});
		expect(payload.iss).toBe("my-client");
	});

	it("produces a unique jti on each call", async () => {
		const { privateKey } = await generateKeyPair("RS256", { extractable: true });
		const pem = await exportPKCS8(privateKey);
		const params = {
			clientId: "client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: pem,
		};

		const [r1, r2] = await Promise.all([
			buildClientJwtAssertion(params),
			buildClientJwtAssertion(params),
		]);

		const p1 = decodeJwt(r1.client_assertion);
		const p2 = decodeJwt(r2.client_assertion);
		expect(p1.jti).not.toBe(p2.jti);
	});

	it("returns the correct JWT_BEARER_URN constant", async () => {
		expect(JWT_BEARER_URN).toBe(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		);
	});

	it("includes kid in the JWT header when the JWK contains a kid field", async () => {
		const { privateKey } = await generateKeyPair("ES256", { extractable: true });
		const privateJwk = {
			...(await exportJWK(privateKey)),
			kid: "my-key-id-123",
		};

		const result = await buildClientJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			privateKey: JSON.stringify(privateJwk),
		});

		const [headerB64] = result.client_assertion.split(".");
		const header = JSON.parse(
			Buffer.from(headerB64, "base64url").toString("utf8"),
		);
		expect(header.kid).toBe("my-key-id-123");
	});
});

describe("buildClientSecretJwtAssertion", () => {
	it("produces a valid HS256 HMAC assertion", async () => {
		const result = await buildClientSecretJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			clientSecret: "super-secret-value",
		});

		expect(result.client_assertion_type).toBe(JWT_BEARER_URN);

		const key = new TextEncoder().encode("super-secret-value");
		const { payload } = await jwtVerify(result.client_assertion, key);
		expect(payload.iss).toBe("my-client");
		expect(payload.sub).toBe("my-client");
		expect(payload.aud).toBe("https://idp.example.com/token");
		expect(typeof payload.jti).toBe("string");
		expect((payload.exp as number) - (payload.iat as number)).toBe(300);
	});

	it("accepts HS384 as an alternative algorithm", async () => {
		const result = await buildClientSecretJwtAssertion({
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			clientSecret: "super-secret-value",
			algorithm: "HS384",
		});

		const key = new TextEncoder().encode("super-secret-value");
		const { payload } = await jwtVerify(result.client_assertion, key, {
			algorithms: ["HS384"],
		});
		expect(payload.iss).toBe("my-client");
	});

	it("produces a unique jti on each call", async () => {
		const params = {
			clientId: "my-client",
			tokenEndpoint: "https://idp.example.com/token",
			clientSecret: "secret",
		};

		const [r1, r2] = await Promise.all([
			buildClientSecretJwtAssertion(params),
			buildClientSecretJwtAssertion(params),
		]);

		const p1 = decodeJwt(r1.client_assertion);
		const p2 = decodeJwt(r2.client_assertion);
		expect(p1.jti).not.toBe(p2.jti);
	});
});
