/** Complete HTTP evidence for the Rust/WASM networking callback contract.
 * HTTP errors resolve normally; transport and decoding failures reject.
 */
export async function mintResponseEnvelope(response: Response): Promise<string> {
  const body = new TextDecoder("utf-8", { fatal: true }).decode(await response.arrayBuffer());
  return JSON.stringify({ status: response.status, body });
}
