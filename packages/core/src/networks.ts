import algosdk from 'algosdk';
import type { NetworkConfig } from './types.js';

/** Public, CORS-enabled endpoints so the web client needs no backend. */
export const NETWORKS: Record<'mainnet' | 'testnet' | 'localnet', NetworkConfig> = {
  mainnet: {
    name: 'mainnet',
    algodUrl: 'https://mainnet-api.algonode.cloud',
    algodToken: '',
    indexerUrl: 'https://mainnet-idx.algonode.cloud',
    indexerToken: '',
  },
  testnet: {
    name: 'testnet',
    algodUrl: 'https://testnet-api.algonode.cloud',
    algodToken: '',
    indexerUrl: 'https://testnet-idx.algonode.cloud',
    indexerToken: '',
  },
  localnet: {
    name: 'localnet',
    algodUrl: 'http://localhost:4001',
    algodToken: 'a'.repeat(64),
    indexerUrl: 'http://localhost:8980',
    indexerToken: '',
  },
};

export interface FalconerClients {
  algod: algosdk.Algodv2;
  indexer?: algosdk.Indexer;
  network: NetworkConfig;
}

/** Split a URL into the base and port algosdk's clients expect. */
function splitUrl(url: string): { base: string; port: string } {
  const parsed = new URL(url);
  const port = parsed.port;
  const base = `${parsed.protocol}//${parsed.hostname}`;
  return { base, port };
}

export function createClients(network: NetworkConfig): FalconerClients {
  const a = splitUrl(network.algodUrl);
  const algod = new algosdk.Algodv2(network.algodToken, a.base, a.port);
  let indexer: algosdk.Indexer | undefined;
  if (network.indexerUrl) {
    const i = splitUrl(network.indexerUrl);
    indexer = new algosdk.Indexer(network.indexerToken ?? '', i.base, i.port);
  }
  return { algod, indexer, network };
}

export function clientsFor(name: 'mainnet' | 'testnet' | 'localnet'): FalconerClients {
  return createClients(NETWORKS[name]);
}
