/**
 * Type-level guard: bytes this library returns must go straight into `fetch` or
 * `new Response` without a copy. That holds only while they are typed
 * `Uint8Array<ArrayBuffer>`, since TypeScript 5.7 reads a bare `Uint8Array` as
 * `Uint8Array<ArrayBufferLike>`, which the DOM `BodyInit` rejects.
 *
 * `tsconfig.json` checks this file and its lib includes DOM. Neither of the
 * other two places can catch the regression: vitest does not typecheck, and
 * `examples/` is checked with Node's types, whose `BodyInit` takes the bare
 * form. Nothing here is called.
 */
import {
	type ChunkedOHTTPClient,
	type ChunkedOHTTPServer,
	frameChunk,
	KeyConfig,
	type OHTTPClient,
	type OHTTPServer,
	type ParsedChunk,
} from "../src/index.js";

declare const bytes: Uint8Array;
declare const client: OHTTPClient;
declare const server: OHTTPServer;
declare const chunkedClient: ChunkedOHTTPClient;
declare const chunkedServer: ChunkedOHTTPServer;
declare const parsed: ParsedChunk;
declare const config: KeyConfig;

export async function everyByteOutputIsABody(): Promise<BodyInit[]> {
	const { encapsulatedRequest, context } = await client.encapsulate(bytes);
	const { request, context: serverContext } = await server.decapsulate(bytes);
	const chunkedOut = await chunkedClient.encapsulate(bytes);
	const chunkedIn = await chunkedServer.decapsulate(bytes);

	return [
		encapsulatedRequest,
		await context.decryptResponse(bytes),
		request,
		await serverContext.encryptResponse(bytes),
		chunkedOut.encapsulatedRequest,
		chunkedIn.request,
		frameChunk(bytes, false),
		parsed.ciphertext,
		KeyConfig.serialize(config),
		KeyConfig.serializeMultiple([config]),
	];
}
