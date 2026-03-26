/**
 * CLI Entry Point for TypeScript ASCII Art Demo
 * 
 * Usage:
 *   tsx src/index.ts server              # Start the server
 *   tsx src/index.ts client [messages]   # Run the client
 */

import { init } from "cdk-spilman-kit";

// Initialize WASM panic hook for better error messages
await init();

const mode = process.argv[2];

if (mode === "server") {
  const { runServer } = await import("./server.js");
  await runServer();
} else if (mode === "client") {
  const messages = process.argv.slice(3);
  const { runClient } = await import("./client.js");
  await runClient(messages);
} else {
  console.log("TypeScript ASCII Art - Spilman Payment Channel Demo");
  console.log();
  console.log("Usage:");
  console.log("  npm run server              # Start the ASCII art server");
  console.log("  npm run client [messages]   # Run the client with messages");
  console.log();
  console.log("Examples:");
  console.log("  npm run server");
  console.log("  npm run client Hello World Cashu");
  console.log("  npm run client \"Hello World\"");
  console.log();
  console.log("Environment variables:");
  console.log("  MINT_URL     - Mint URL (default: http://localhost:3338)");
  console.log("  SERVER_URL   - Server URL (default: http://localhost:5002)");
  console.log("  PORT         - Server port (default: 5002)");
  process.exit(1);
}
