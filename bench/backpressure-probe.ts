/** Runtime-neutral source instrumentation for streaming backpressure probes. */

export interface SourceProbe {
	readonly stream: ReadableStream<Uint8Array>;
	readonly bytesRead: () => number;
	readonly pulls: () => number;
}

export function measuredSource(totalBytes: number, chunkSize: number): SourceProbe {
	let produced = 0;
	let pullCount = 0;

	return {
		stream: new ReadableStream<Uint8Array>({
			pull(controller) {
				if (produced >= totalBytes) {
					controller.close();
					return;
				}

				const size = Math.min(chunkSize, totalBytes - produced);
				// Distinct backing stores make eager read-ahead create real pressure.
				const chunk = new Uint8Array(size);
				chunk[0] = pullCount & 0xff;
				produced += size;
				pullCount++;
				controller.enqueue(chunk);
			},
		}),
		bytesRead: () => produced,
		pulls: () => pullCount,
	};
}
