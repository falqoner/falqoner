/**
 * Which network a node is on, and whether this page may execute there. The
 * policy is core's (SAFE-03b): the guarded ceremony applies it before
 * anything is signed, and the journal refuses a stored record for a network
 * it refuses.
 */
export {
  genesisOfParams as genesisOf,
  genesisRefusal,
  pinClients,
  type NetworkGenesis as Genesis,
} from '@falqoner/core';

export type NetworkName = 'mainnet' | 'testnet' | 'localnet';
