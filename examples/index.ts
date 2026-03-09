// Copyright (c) 2024
// Licensed under the MIT license

import { obliviousHTTPWithRequestResponse } from "./bhttp.example.js";
import { chunkedHttpApi, chunkedHttpLargeBody } from "./chunked-http.example.js";
import { chunkedOHTTP } from "./chunked.example.js";
import { postQuantumOHTTP } from "./mlkem.example.js";
import { obliviousHTTP } from "./ohttp.example.js";

async function main() {
	const results = await Promise.all([
		obliviousHTTP().then((ok) => ({ name: "Oblivious HTTP (RFC 9458)", ok })),
		chunkedOHTTP().then((ok) => ({ name: "Chunked OHTTP (draft-08)", ok })),
		obliviousHTTPWithRequestResponse().then((ok) => ({ name: "OHTTP Request/Response API", ok })),
		postQuantumOHTTP().then((ok) => ({ name: "Post-Quantum OHTTP (ML-KEM-768)", ok })),
		chunkedHttpApi().then((ok) => ({ name: "Chunked OHTTP HTTP API", ok })),
		chunkedHttpLargeBody().then((ok) => ({ name: "Chunked OHTTP Large Body", ok })),
	]);

	console.log("\nExamples:");
	for (const { name, ok } of results) {
		console.log(`  ${name}: ${ok ? "PASS" : "FAIL"}`);
	}

	const allPassed = results.every((r) => r.ok);
	process.exit(allPassed ? 0 : 1);
}

main();
