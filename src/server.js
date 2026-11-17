import { loadConfig } from "./config.js";
import { createStore } from "./store.js";
import { createApp } from "./app.js";

const config = loadConfig();
const store = createStore(config.dbPath);
const server = createApp({ config, store });
server.listen(config.port, () => console.log(`connect-to-anything listening on ${config.publicUrl}`));

for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(() => { store.close(); process.exit(0); }));
