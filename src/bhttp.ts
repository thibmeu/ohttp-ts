import { BHttpDecoder, BHttpEncoder } from "bhttp-ts";

let encoder: BHttpEncoder | undefined;
let decoder: BHttpDecoder | undefined;

export const bhttpEncoder = (): BHttpEncoder => (encoder ??= new BHttpEncoder());
export const bhttpDecoder = (): BHttpDecoder => (decoder ??= new BHttpDecoder());
