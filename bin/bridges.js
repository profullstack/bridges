#!/usr/bin/env node
// bridges: set up an account bridge between a host site and an app.
import { pkceChallenge, randomToken } from '../index.js';

const [command, ...args] = process.argv.slice(2);

const HELP = `bridges: link a host site's accounts to an app (OAuth 2.1 code + PKCE)

Usage:
  bridges keygen                         print a new client secret
  bridges client <client_id> <callback>  print a host-side client entry and the
                                         matching app-side settings, with a fresh secret
  bridges check <authorize_url> <client_id> <callback>
                                         ask the host for a silent sign-in and report
                                         what it answers (login_required means it works)
  bridges help

Docs: https://github.com/profullstack/bridges#readme`;

async function main() {
  switch (command) {
    case 'keygen':
      console.log(randomToken(32));
      return;
    case 'client': {
      const [clientId, callback] = args;
      if (!clientId || !callback) throw new Error('usage: bridges client <client_id> <callback_url>');
      new URL(callback);
      const secret = randomToken(32);
      console.log(
        JSON.stringify(
          {
            host: { clients: { [clientId]: { secret, redirectUris: [callback] } } },
            app: { clientId, clientSecret: secret, redirectUri: callback },
          },
          null,
          2,
        ),
      );
      return;
    }
    case 'check': {
      const [authorize, clientId, callback] = args;
      if (!authorize || !clientId || !callback) throw new Error('usage: bridges check <authorize_url> <client_id> <callback_url>');
      const url = new URL(authorize);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callback);
      url.searchParams.set('state', 'check');
      url.searchParams.set('code_challenge', await pkceChallenge(randomToken(32)));
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('prompt', 'none');
      const response = await fetch(url, { redirect: 'manual' });
      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        const back = new URL(location);
        const error = back.searchParams.get('error');
        console.log(`${response.status} -> ${back.origin}${back.pathname}`);
        console.log(error ? `error=${error}` : 'code issued');
        process.exitCode = error === 'login_required' || !error ? 0 : 1;
      } else {
        console.log(`${response.status}: ${(await response.text()).trim().slice(0, 300)}`);
        process.exitCode = 1;
      }
      return;
    }
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      return;
    default:
      throw new Error(`unknown command: ${command}\n\n${HELP}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
