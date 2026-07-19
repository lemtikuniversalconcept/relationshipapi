import { app } from './app';
import { config, validateProductionConfig } from './config';

async function main(): Promise<void> {
  validateProductionConfig();
  const host = process.env.HOST || '0.0.0.0';
  await app.ready();
  await app.listen({ port: config.port, host });
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});
