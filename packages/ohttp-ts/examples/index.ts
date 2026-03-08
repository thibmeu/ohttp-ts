// Copyright (c) 2024
// Licensed under the MIT license

import { obliviousHTTP } from "./ohttp.example.js";
import { chunkedOHTTP } from "./chunked.example.js";

async function main() {
	const results = await Promise.all([
		obliviousHTTP().then((ok) => ({ name: "Oblivious HTTP (RFC 9458)", ok })),
		chunkedOHTTP().then((ok) => ({ name: "Chunked OHTTP (draft-08)", ok })),
	]);

	console.log("\nExamples:");
	for (const { name, ok } of results) {
		console.log(`  ${name}: ${ok ? "PASS" : "FAIL"}`);
	}

	const allPassed = results.every((r) => r.ok);
	process.exit(allPassed ? 0 : 1);
}

main();
